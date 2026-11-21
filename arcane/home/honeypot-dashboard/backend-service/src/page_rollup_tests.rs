//! #3910: the snapshot-served handlers against a stand-in Elasticsearch.
//!
//! Each test stores page documents the way the worker does
//! (`page_rollup::snapshot_doc`), answers every `_search` with a fixed live
//! answer, and records which searches the handler made. A fresh snapshot
//! must answer without a search and parse exactly like the live answer; a
//! stale, foreign-schema or missing snapshot must send the handler to its
//! live search; a parameterised request must stay live; and the worker must
//! not store a partial answer.
//!
//! The tests hold `dashboard::self_ips_env()` for their whole body, across
//! awaits, so `HONEYPOT_SELF_IPS` cannot change between building a snapshot
//! and the handler checking it. Each test runs on its own current-thread
//! runtime, so nothing else waits on that lock inside one.
#![allow(clippy::await_holding_lock)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Router;
use chrono::{Duration, Utc};
use serde_json::{json, Value};

use crate::page_rollup::{self, snapshot_doc};
use crate::{audit, config_history, es, obs, trust, AppState};

#[derive(Default)]
struct Seen {
    searches: Vec<String>,
    writes: Vec<String>,
}

struct Stub {
    docs: HashMap<String, Value>,
    answer: Value,
    seen: Mutex<Seen>,
}

async fn answer(State(stub): State<Arc<Stub>>, method: Method, uri: Uri, body: Bytes) -> axum::response::Response {
    let path = uri.path().to_string();
    if let Some(id) = path.strip_prefix(&format!("/{}/_doc/", page_rollup::INDEX)) {
        if method == Method::GET {
            return match stub.docs.get(id) {
                Some(doc) => axum::Json(json!({"_id": id, "found": true, "_seq_no": 1, "_primary_term": 1, "_source": doc})).into_response(),
                None => (StatusCode::NOT_FOUND, axum::Json(json!({"_id": id, "found": false}))).into_response(),
            };
        }
        stub.seen.lock().unwrap().writes.push(id.to_string());
        return (StatusCode::CREATED, axum::Json(json!({"result": "created"}))).into_response();
    }
    if path.ends_with("/_search") {
        let _ = body;
        stub.seen.lock().unwrap().searches.push(path);
        return axum::Json(stub.answer.clone()).into_response();
    }
    (StatusCode::NOT_FOUND, axum::Json(json!({"error": "not stubbed"}))).into_response()
}

async fn state_with(docs: HashMap<String, Value>, live: Value) -> (AppState, Arc<Stub>) {
    let stub = Arc::new(Stub { docs, answer: live, seen: Mutex::new(Seen::default()) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let url = format!("http://{}", listener.local_addr().expect("stub addr"));
    let app = Router::new().fallback(answer).with_state(stub.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    let state = AppState {
        es: Arc::new(es::Es::connect(&url).expect("client")),
        trust: Arc::new(trust::Trust::bff_only(None)),
        audit: Arc::new(audit::AuditLogger::new(std::env::temp_dir().join("apiary-3910-audit.jsonl"))),
        config_history: Arc::new(config_history::ConfigHistory::new(std::env::temp_dir().join("apiary-3910-history.jsonl"))),
        observability: Arc::new(obs::Obs::new(String::new())),
    };
    (state, stub)
}

fn searches(stub: &Stub) -> Vec<String> {
    stub.seen.lock().unwrap().searches.clone()
}

/// An Elasticsearch answer carrying `aggregations`.
fn es_answer(aggregations: Value) -> Value {
    json!({
        "took": 12,
        "timed_out": false,
        "_shards": {"total": 3, "successful": 3, "failed": 0},
        "hits": {"total": {"value": 42, "relation": "eq"}, "hits": []},
        "aggregations": aggregations
    })
}

fn stacks(key: &str, ips: u64) -> Value {
    es_answer(json!({"stacks": {"buckets": [{"key": key, "doc_count": ips * 10, "ips": {"value": ips}}]}}))
}

fn fresh(id: &str, result: &Value) -> (String, Value) {
    (id.to_string(), snapshot_doc(id, Utc::now() - Duration::seconds(30), result))
}

async fn tcp_stack(state: AppState) -> Value {
    let response = crate::charts::tcp_stack_clusters(State(state)).await.expect("200");
    serde_json::to_value(&response.0).unwrap()
}

#[tokio::test]
async fn a_recent_snapshot_answers_without_a_search_and_parses_like_live() {
    let _env = crate::dashboard::self_ips_env();
    let snapshot = stacks("t_snapshot", 7);
    let (state, stub) = state_with(HashMap::from([fresh(page_rollup::TCP_STACK_CLUSTERS, &snapshot)]), stacks("t_live", 3)).await;
    assert_eq!(tcp_stack(state).await, json!([{"name": "t_snapshot", "value": 7}]));
    assert!(searches(&stub).is_empty(), "served from the snapshot: {:?}", searches(&stub));

    // The same answer read live gives the same payload.
    let (state, stub) = state_with(HashMap::new(), snapshot).await;
    assert_eq!(tcp_stack(state).await, json!([{"name": "t_snapshot", "value": 7}]));
    assert_eq!(searches(&stub).len(), 1);
}

#[tokio::test]
async fn a_stale_foreign_or_missing_snapshot_falls_back_to_the_live_search() {
    let _env = crate::dashboard::self_ips_env();
    let id = page_rollup::TCP_STACK_CLUSTERS;
    let snapshot = stacks("t_snapshot", 7);
    let stale = snapshot_doc(id, Utc::now() - Duration::seconds(901), &snapshot);
    let mut schema = snapshot_doc(id, Utc::now(), &snapshot);
    schema["schema"] = json!(1);
    let mut request = snapshot_doc(id, Utc::now(), &snapshot);
    request["request"] = json!("written for another request");
    for (case, docs) in [
        ("stale", HashMap::from([(id.to_string(), stale)])),
        ("schema", HashMap::from([(id.to_string(), schema)])),
        ("request", HashMap::from([(id.to_string(), request)])),
        ("missing", HashMap::new()),
    ] {
        let (state, stub) = state_with(docs, stacks("t_live", 3)).await;
        assert_eq!(tcp_stack(state).await, json!([{"name": "t_live", "value": 3}]), "{case}");
        assert_eq!(searches(&stub).len(), 1, "{case}: one live search");
    }
}

#[tokio::test]
async fn only_the_unfiltered_explorer_reads_the_facet_snapshots() {
    let _env = crate::dashboard::self_ips_env();
    let snapshot = es_answer(json!({"sensors": {"buckets": [{"key": "cowrie", "doc_count": 5}]}}));
    let providers = es_answer(json!({"providers": {"buckets": [{"key": "hosting", "doc_count": 4}]}}));
    let docs = HashMap::from([
        fresh(page_rollup::FACETS_EVENTS, &snapshot),
        fresh(page_rollup::FACETS_EVENTS_PROVIDERS, &providers),
    ]);
    let live = es_answer(json!({"sensors": {"buckets": [{"key": "dionaea", "doc_count": 9}]}}));

    // What the events page sends: `offset=0`, no filter.
    let (state, stub) = state_with(docs.clone(), live.clone()).await;
    let default = serde_json::from_value(json!({"offset": 0})).unwrap();
    let facets = crate::facets::get(State(state), Path("events".to_string()), Query(default)).await.expect("200").0;
    assert!(searches(&stub).is_empty(), "{:?}", searches(&stub));
    assert_eq!((facets.total, facets.sensors[0].value.as_str(), facets.providers[0].value.as_str()), (42, "cowrie", "hosting"));

    // A filter makes it another request: live, both searches.
    let (state, stub) = state_with(docs, live).await;
    let filtered = serde_json::from_value(json!({"sensor": "cowrie"})).unwrap();
    let facets = crate::facets::get(State(state), Path("events".to_string()), Query(filtered)).await.expect("200").0;
    assert_eq!(searches(&stub).len(), 2);
    assert_eq!(facets.sensors[0].value, "dionaea");
}

#[tokio::test]
async fn only_the_hubs_catalog_request_reads_the_ioc_snapshot() {
    let _env = crate::dashboard::self_ips_env();
    let docs = HashMap::from([fresh(page_rollup::IOC_CATALOG, &es_answer(json!({})))]);
    let call = |query: Value, docs: HashMap<String, Value>| async move {
        let (state, stub) = state_with(docs, es_answer(json!({}))).await;
        let query = serde_json::from_value(query).unwrap();
        let response = crate::entity_details::ioc_catalog(State(state), Query(query)).await;
        assert!(response.is_ok());
        searches(&stub).len()
    };
    assert_eq!(call(json!({"size": 100, "range": "30d"}), docs.clone()).await, 0);
    assert_eq!(call(json!({"size": 100, "range": "7d"}), docs.clone()).await, 1);
    assert_eq!(call(json!({"size": 100, "range": "30d", "kind": "hash"}), docs.clone()).await, 1);
    assert_eq!(call(json!({}), docs).await, 1, "the endpoint default (7d, 25) is not the hub's request");
}

#[tokio::test]
async fn each_ics_protocol_falls_back_on_its_own() {
    let _env = crate::dashboard::self_ips_env();
    let fns = |key: &str| es_answer(json!({"fn": {"buckets": [{"key": key, "doc_count": 2}]}}));
    let docs = HashMap::from([fresh("ics-functions-modbus", &fns("READ_COILS"))]);
    let (state, stub) = state_with(docs, fns("live")).await;
    let bar = crate::charts::ics_functions(State(state)).await.expect("200").0;
    assert_eq!(
        bar.categories,
        vec!["modbus: READ_COILS", "s7comm: live", "dnp3: live", "iec104: live"]
    );
    assert_eq!(searches(&stub).len(), 3, "only the three protocols without a snapshot");
}

#[tokio::test]
async fn the_sankey_snapshot_answers_before_the_rollup() {
    let _env = crate::dashboard::self_ips_env();
    let groups = es_answer(json!({
        "sessions": {"buckets": [{"key": "s1", "doc_count": 3, "techs": {"buckets": [{"key": "T1110"}, {"key": "T1059"}]}}]},
        "ips": {"buckets": []}
    }));
    let (state, stub) = state_with(HashMap::from([fresh(page_rollup::KILL_CHAIN_SANKEY, &groups)]), es_answer(json!({}))).await;
    let data = serde_json::to_value(crate::kill_chain::sankey(State(state)).await.expect("200").0).unwrap();
    assert!(searches(&stub).is_empty(), "{:?}", searches(&stub));
    assert_eq!(data["nodes"], json!([{"name": "Execution"}, {"name": "Credential Access"}]));
    assert_eq!(data["links"], json!([{"source": "Execution", "target": "Credential Access", "value": 1}]));
}

#[tokio::test]
async fn the_worker_stores_complete_answers_and_skips_partial_ones() {
    let _env = crate::dashboard::self_ips_env();
    let (state, stub) = state_with(HashMap::new(), es_answer(json!({"x": {"value": 1}}))).await;
    page_rollup::write_cycle(&state).await;
    let pages = stub.seen.lock().unwrap().writes.len();
    assert_eq!(pages, searches(&stub).len(), "one write per page searched");
    assert!(pages >= 17);

    let mut partial = es_answer(json!({"x": {"value": 1}}));
    partial["_shards"]["failed"] = json!(1);
    let (state, stub) = state_with(HashMap::new(), partial).await;
    page_rollup::write_cycle(&state).await;
    assert!(stub.seen.lock().unwrap().writes.is_empty(), "a partial answer is never stored");
}
