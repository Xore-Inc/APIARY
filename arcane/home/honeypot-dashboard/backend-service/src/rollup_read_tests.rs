//! #3929: the handlers that read the hourly rollups, against a stand-in
//! Elasticsearch that stores the hour documents the way the writer does
//! (`bucket` as `%Y-%m-%dT%H:00Z`, `family` and `modbus_detail_excluded`).
//!
//! Until #3929 no stored hour ever parsed, so every one of these handlers ran
//! its live search; these pin which searches each handler makes now that the
//! hours parse.
#![allow(clippy::await_holding_lock)]

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Router;
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use serde_json::{json, Value};

use crate::{audit, config_history, es, obs, trust, AppState};

struct Stub {
    overview: Vec<Value>,
    attack: Vec<Value>,
    live: Value,
    seen: Mutex<Vec<(String, Value)>>,
}

fn bucket_of(doc: &Value) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(doc["bucket"].as_str()?, "%Y-%m-%dT%H:%MZ").ok().map(|naive| naive.and_utc())
}

/// Every `terms` on `family.keyword` anywhere in the body, and whether the
/// body asks for the current fleet scope.
fn family_filter(body: &Value, families: &mut Vec<String>, scoped: &mut bool) {
    match body {
        Value::Object(map) => {
            if let Some(values) = map.get("terms").and_then(|terms| terms.get("family.keyword")).and_then(Value::as_array) {
                families.extend(values.iter().filter_map(Value::as_str).map(String::from));
            }
            if map.get("term").and_then(|term| term.get("modbus_detail_excluded")) == Some(&json!(true)) {
                *scoped = true;
            }
            map.values().for_each(|value| family_filter(value, families, scoped));
        }
        Value::Array(items) => items.iter().for_each(|value| family_filter(value, families, scoped)),
        _ => {}
    }
}

fn hits(docs: Vec<Value>) -> Value {
    json!({
        "took": 1, "timed_out": false, "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {"total": {"value": docs.len(), "relation": "eq"}, "hits": docs.into_iter().map(|doc| json!({"_source": doc})).collect::<Vec<_>>()}
    })
}

async fn answer(State(stub): State<Arc<Stub>>, method: Method, uri: Uri, body: Bytes) -> axum::response::Response {
    let path = uri.path().to_string();
    if method == Method::GET && path.contains("/_doc/") {
        return (StatusCode::NOT_FOUND, axum::Json(json!({"found": false}))).into_response();
    }
    if !path.ends_with("/_search") {
        return (StatusCode::NOT_FOUND, axum::Json(json!({"error": "not stubbed"}))).into_response();
    }
    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    stub.seen.lock().unwrap().push((path.clone(), request.clone()));
    if path.starts_with("/overview-rollup-v1/") {
        let (mut families, mut scoped) = (Vec::new(), false);
        family_filter(&request, &mut families, &mut scoped);
        let since = request["query"]["bool"]["filter"][0]["range"]["bucket"]["gte"]
            .as_str()
            .and_then(|label| DateTime::parse_from_rfc3339(label).ok())
            .map(|since| since.with_timezone(&Utc));
        let docs = stub
            .overview
            .iter()
            .filter(|doc| families.iter().any(|family| doc["family"] == json!(family)))
            .filter(|doc| !scoped || doc["modbus_detail_excluded"] == json!(true))
            .filter(|doc| since.is_none_or(|since| bucket_of(doc).is_some_and(|hour| hour >= since)))
            .cloned()
            .collect();
        return axum::Json(hits(docs)).into_response();
    }
    if path.starts_with("/attack-rollup-v1/") {
        return axum::Json(hits(stub.attack.clone())).into_response();
    }
    if path.starts_with("/geo-rollup-v1/") {
        return axum::Json(hits(Vec::new())).into_response();
    }
    axum::Json(stub.live.clone()).into_response()
}

async fn state_with(overview: Vec<Value>, attack: Vec<Value>, live: Value) -> (AppState, Arc<Stub>) {
    let stub = Arc::new(Stub { overview, attack, live, seen: Mutex::new(Vec::new()) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let url = format!("http://{}", listener.local_addr().expect("stub addr"));
    let app = Router::new().fallback(answer).with_state(stub.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    let state = AppState {
        es: Arc::new(es::Es::connect(&url).expect("client")),
        trust: Arc::new(trust::Trust::bff_only(None)),
        audit: Arc::new(audit::AuditLogger::new(std::env::temp_dir().join("apiary-3929-audit.jsonl"))),
        config_history: Arc::new(config_history::ConfigHistory::new(std::env::temp_dir().join("apiary-3929-history.jsonl"))),
        observability: Arc::new(obs::Obs::new(String::new())),
    };
    (state, stub)
}

fn key(hour: DateTime<Utc>) -> String {
    hour.format("%Y-%m-%dT%H:00Z").to_string()
}

fn this_hour() -> DateTime<Utc> {
    let secs = Utc::now().timestamp();
    DateTime::from_timestamp(secs - secs.rem_euclid(3600), 0).unwrap()
}

/// `count` hour docs ending at the current hour (two spare hours before the
/// 48 h window, so a clock tick across the hour cannot uncover it).
fn fleet_docs(count: i64, events: u64, scoped: bool) -> Vec<Value> {
    (0..count)
        .map(|back| {
            let hour = this_hour() - Duration::hours(back);
            let mut doc = json!({
                "bucket": key(hour), "family": "_all", "events": events, "logins": 10, "clean_events": events,
                "sensors": [{"key": "cowrie", "count": events}, {"key": "zeek", "count": 5}]
            });
            if scoped {
                doc["modbus_detail_excluded"] = json!(true);
            }
            doc
        })
        .collect()
}

fn family_docs(family: &str, count: i64, bytes: f64) -> Vec<Value> {
    (0..count)
        .map(|back| json!({"bucket": key(this_hour() - Duration::hours(back)), "family": family, "bytes": bytes, "packets": 3.0}))
        .collect()
}

fn searches(stub: &Stub) -> Vec<String> {
    stub.seen.lock().unwrap().iter().map(|(path, _)| path.clone()).collect()
}

fn event_searches(stub: &Stub) -> Vec<String> {
    searches(stub).into_iter().filter(|path| !path.contains("-rollup-v1")).collect()
}

fn live_answer() -> Value {
    json!({
        "took": 1, "timed_out": false, "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {"total": {"value": 777, "relation": "eq"}, "hits": []},
        "aggregations": {}
    })
}

#[tokio::test]
async fn kpis_are_served_from_the_stored_hours() {
    let (state, stub) = state_with(fleet_docs(50, 1000, true), Vec::new(), live_answer()).await;
    let kpis = serde_json::to_value(&crate::overview::kpis(State(state)).await.expect("200").0).unwrap();
    assert_eq!(kpis["total"], 48_000, "48 whole hours of 1000 events");
    assert_eq!(kpis["last24h"], 24_000);
    assert_eq!(kpis["previous24h"], 24_000);
    assert_eq!(kpis["logins"], 480);
    assert_eq!(kpis["hourly"].as_array().map(Vec::len), Some(24));
    assert!(searches(&stub).iter().any(|path| path.starts_with("/overview-rollup-v1/")));
    // Only the live window (unique addresses, sessions) is searched live;
    // the fallback's own events/hourly/logins aggregations never are.
    for (_, body) in stub.seen.lock().unwrap().iter() {
        assert!(body["aggs"].get("last24h").is_none(), "the fallback search ran: {body}");
    }
}

#[tokio::test]
async fn fleet_hours_from_before_the_modbus_exclusion_are_not_served() {
    // Unmarked fleet docs counted another set of events: the window reads as
    // not covered and the handler answers from its own search.
    let (state, stub) = state_with(fleet_docs(50, 1000, false), Vec::new(), live_answer()).await;
    let kpis = serde_json::to_value(&crate::overview::kpis(State(state)).await.expect("200").0).unwrap();
    assert_eq!(kpis["total"], 777, "answered by the live search");
    assert!(!event_searches(&stub).is_empty());
}

#[tokio::test]
async fn the_attack_grid_sums_the_stored_technique_docs() {
    let attack: Vec<Value> = (0..48)
        .map(|back| json!({"kind": "tech", "bucket": key(this_hour() - Duration::hours(back)), "technique": "T1110", "count": 7}))
        .collect();
    let (state, stub) = state_with(fleet_docs(50, 1000, true), attack, live_answer()).await;
    let grid = serde_json::to_value(&crate::kill_chain::attck_coverage(State(state)).await.expect("200").0).unwrap();
    assert_eq!(grid["cells"][0]["count"], 336);
    assert!(event_searches(&stub).is_empty(), "no live search: {:?}", event_searches(&stub));
}

#[tokio::test]
async fn the_sankey_stays_on_the_live_grouping() {
    // The hourly link docs count a group once per hour; the live grouping
    // counts it once. They disagreed 3x to 30x on production (#3929).
    let attack = vec![json!({"kind": "link", "bucket": key(this_hour()), "source": "Reconnaissance", "target": "Credential Access", "count": 999})];
    let live = json!({
        "took": 1, "timed_out": false, "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        "aggregations": {
            "sessions": {"buckets": [{"key": "s1", "techs": {"buckets": [{"key": "T1595"}, {"key": "T1110"}]}}]},
            "ips": {"buckets": []}
        }
    });
    let (state, stub) = state_with(fleet_docs(50, 1000, true), attack, live).await;
    let sankey = serde_json::to_value(&crate::kill_chain::sankey(State(state)).await.expect("200").0).unwrap();
    assert_eq!(sankey["links"], json!([{"source": "Reconnaissance", "target": "Credential Access", "value": 1}]));
    assert!(!searches(&stub).iter().any(|path| path.starts_with("/attack-rollup-v1/")));
}

#[tokio::test]
async fn netflow_reads_zeek_and_only_falls_back_to_suricata_when_zeek_is_empty() {
    // Zeek has data: one rollup read, on the keyword field.
    let mut docs = family_docs("zeek", 170, 100.0);
    docs.extend(family_docs("suricata-netflow", 170, 5.0));
    let (state, stub) = state_with(docs, Vec::new(), live_answer()).await;
    let series = crate::charts::netflow_bytes(State(state)).await.expect("200").0;
    assert_eq!(series[0].points.len(), 168);
    assert!(series[0].points.iter().all(|point| point.value == 100.0));
    let rollup_reads: Vec<Value> = stub.seen.lock().unwrap().iter().filter(|(path, _)| path.starts_with("/overview-rollup-v1/")).map(|(_, body)| body.clone()).collect();
    assert_eq!(rollup_reads.len(), 1, "the Suricata leg is not read");
    assert!(rollup_reads[0].to_string().contains("\"family.keyword\":[\"zeek\"]"));
    assert!(event_searches(&stub).is_empty());

    // Zeek is silent: the Suricata leg, whose two-token family name only
    // matches on the keyword field, supplies the series.
    let mut docs = family_docs("zeek", 170, 0.0);
    docs.extend(family_docs("suricata-netflow", 170, 5.0));
    let (state, stub) = state_with(docs, Vec::new(), live_answer()).await;
    let series = crate::charts::netflow_bytes(State(state)).await.expect("200").0;
    assert!(series[0].points.iter().all(|point| point.value == 5.0));
    assert!(searches(&stub).iter().filter(|path| path.starts_with("/overview-rollup-v1/")).count() == 2);
    assert!(event_searches(&stub).is_empty());
}

#[tokio::test]
async fn the_heatmap_is_served_from_the_stored_hours() {
    let _env = crate::dashboard::self_ips_env();
    let (state, stub) = state_with(fleet_docs(50, 1000, true), Vec::new(), live_answer()).await;
    let query = Query(serde_json::from_value(json!({"parts": "heatmap"})).unwrap());
    let dashboard = serde_json::to_value(&crate::dashboard::dashboard(State(state), query).await.expect("200").0).unwrap();
    let rows = dashboard["heatmap"].as_array().expect("heatmap rows");
    assert_eq!(rows[0]["sensor"], "cowrie");
    assert_eq!(rows[0]["cells"].as_array().map(Vec::len), Some(24));
    assert_eq!(rows[0]["cells"][23]["count"], 1000);
    assert!(event_searches(&stub).is_empty(), "no live search: {:?}", event_searches(&stub));
}
