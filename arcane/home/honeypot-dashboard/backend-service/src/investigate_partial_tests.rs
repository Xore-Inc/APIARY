//! #3918: the IP profile against a stand-in Elasticsearch that answers 200
//! with failed shards, as the real one did for a terms aggregation on the
//! `text` field `suricata.eve.alert.signature`.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Router;
use serde_json::{json, Value};

use crate::{audit, config_history, es, obs, trust, AppState};

struct Stub {
    failed_shards: u64,
    bodies: Mutex<Vec<Value>>,
}

async fn answer(State(stub): State<Arc<Stub>>, method: Method, uri: Uri, body: Bytes) -> axum::response::Response {
    if method == Method::POST && uri.path().ends_with("/_search") {
        stub.bodies.lock().unwrap().push(serde_json::from_slice(&body).unwrap_or(Value::Null));
        let failures = if stub.failed_shards > 0 {
            json!([{"reason": {"reason": "Fielddata is disabled on [suricata.eve.alert.signature]"}}])
        } else {
            json!([])
        };
        return axum::Json(json!({
            "took": 1, "timed_out": false,
            "_shards": {"total": 6, "successful": 6 - stub.failed_shards, "failed": stub.failed_shards, "failures": failures},
            "hits": {"total": {"value": 14, "relation": "eq"}, "hits": []},
            "aggregations": {"alerts": {"buckets": [{"key": "ET SCAN Example", "doc_count": 3}]}}
        }))
        .into_response();
    }
    (StatusCode::NOT_FOUND, axum::Json(json!({"error": "not stubbed"}))).into_response()
}

async fn profile(failed_shards: u64) -> (Value, Arc<Stub>) {
    let stub = Arc::new(Stub { failed_shards, bodies: Mutex::new(Vec::new()) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let url = format!("http://{}", listener.local_addr().expect("stub addr"));
    let app = Router::new().fallback(answer).with_state(stub.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    let state = AppState {
        es: Arc::new(es::Es::connect(&url).expect("client")),
        trust: Arc::new(trust::Trust::bff_only(None)),
        audit: Arc::new(audit::AuditLogger::new(std::env::temp_dir().join("apiary-3918-audit.jsonl"))),
        config_history: Arc::new(config_history::ConfigHistory::new(std::env::temp_dir().join("apiary-3918-history.jsonl"))),
        observability: Arc::new(obs::Obs::new(String::new())),
    };
    let profile = crate::investigate::ip(State(state), Path("203.0.113.9".to_string())).await.expect("200");
    (serde_json::to_value(&profile.0).unwrap(), stub)
}

#[tokio::test]
async fn a_complete_profile_carries_no_partial_flag_and_asks_for_the_keyword_field() {
    let (profile, stub) = profile(0).await;
    assert!(profile.get("partial").is_none(), "{profile}");
    assert_eq!(profile["alerts"][0]["key"], "ET SCAN Example");
    assert_eq!(profile["alerts"][0]["count"], 3);
    let bodies = stub.bodies.lock().unwrap();
    let agg = bodies.iter().find(|body| body["aggs"].get("alerts").is_some()).expect("the profile's aggregation search");
    assert_eq!(agg["aggs"]["alerts"]["terms"]["field"], "suricata.eve.alert.signature.keyword");
}

#[tokio::test]
async fn failed_shards_mark_the_profile_partial() {
    let (profile, _stub) = profile(4).await;
    assert_eq!(profile["partial"], json!(true));
    assert_eq!(profile["total"], 14, "the answer itself is still served");
}

/// The profile aggregates on fields the Suricata template has to keep
/// aggregatable: a `text` field fails every shard it is mapped on.
#[test]
fn every_suricata_field_the_profile_aggregates_on_is_a_keyword_sub_field() {
    let source = include_str!("investigate.rs");
    let template = include_str!("../../../honeypot-init/analysis/elasticsearch-setup.sh");
    // The template declares the alert signature as text with a keyword
    // sub-field, so `.keyword` exists on every new index, exactly as the
    // dynamic default gave the older ones.
    let start = template.find("_index_template/suricata-events").expect("suricata-events template");
    let end = start + template[start..].find("\nJSON\n").expect("end of the template body");
    let section = &template[start..end];
    for field in ["signature", "category"] {
        let needle = format!("\"{field}\": {{ \"type\": \"text\", \"fields\": {{ \"keyword\": {{ \"type\": \"keyword\", \"ignore_above\": 256 }} }} }}");
        assert!(section.contains(&needle), "suricata-events must map alert.{field} as text with a keyword sub-field");
    }
    // And the profile never aggregates on the bare `suricata.*` field.
    for line in source.lines().filter(|line| line.contains("\"terms\": {\"field\": \"suricata.")) {
        assert!(line.contains(".keyword"), "terms aggregation on a text field: {line}");
    }
}
