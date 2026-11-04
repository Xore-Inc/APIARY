//! Detail and drill-down documents that are not covered by the store list routes.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::AppState;

type Response = Result<(StatusCode, Json<Value>), (StatusCode, String)>;

#[derive(Deserialize)]
pub struct RangeQuery {
    #[serde(default = "default_range")]
    pub range: String,
}

fn default_range() -> String { "24h".into() }

fn range(query: &RangeQuery) -> Result<String, (StatusCode, String)> {
    match query.range.as_str() {
        "1h" | "6h" | "24h" | "7d" | "30d" => Ok(format!("now-{}", query.range)),
        _ => Err((StatusCode::BAD_REQUEST, "range must be 1h, 6h, 24h, 7d, or 30d".into())),
    }
}

fn validate_id(id: String) -> Result<String, (StatusCode, String)> {
    let id = id.trim().to_string();
    if id.is_empty() || id.len() > 512 { Err((StatusCode::BAD_REQUEST, "invalid id".into())) } else { Ok(id) }
}

async fn doc(state: &AppState, index: &str, id: String) -> Response {
    let id = validate_id(id)?;
    match state.es.get_doc(index, &id).await.map_err(bad_gateway)? {
        Some(doc) => Ok((StatusCode::OK, Json(doc))),
        None => Ok((StatusCode::NOT_FOUND, Json(Value::Null))),
    }
}

async fn first(state: &AppState, indices: &[&str], query: Value) -> Response {
    let result = state.es.search_index(indices, json!({"size": 1, "query": query})).await.map_err(bad_gateway)?;
    match result["hits"]["hits"].as_array().and_then(|hits| hits.first()) {
        Some(hit) => Ok((StatusCode::OK, Json(hit["_source"].clone()))),
        None => Ok((StatusCode::NOT_FOUND, Json(Value::Null))),
    }
}

// ponytail: hard-coded size=100, no pagination — add StoreQuery offset/size if callers need >100
async fn page(state: &AppState, indices: &[&str], query: Value, sort: Value) -> Response {
    let result = state.es.search_index(indices, json!({"size": 100, "track_total_hits": true, "sort": sort, "query": query})).await.map_err(bad_gateway)?;
    let rows = result["hits"]["hits"].as_array().map(|hits| hits.iter().map(|hit| hit["_source"].clone()).collect::<Vec<_>>()).unwrap_or_default();
    Ok((StatusCode::OK, Json(json!({"total": result["hits"]["total"]["value"], "rows": rows}))))
}

async fn source_page(state: &AppState, indices: &[&str], query: Value, sort: Value) -> Response {
    let result = state.es.search_index(indices, json!({"size": 100, "track_total_hits": true, "sort": sort, "query": query})).await.map_err(bad_gateway)?;
    let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
    if hits.is_empty() { return Ok((StatusCode::NOT_FOUND, Json(Value::Null))); }
    let rows: Vec<Value> = hits.into_iter().map(|hit| hit["_source"].clone()).collect();
    Ok((StatusCode::OK, Json(json!({"total": result["hits"]["total"]["value"], "rows": rows}))))
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) { (StatusCode::BAD_GATEWAY, error.to_string()) }

macro_rules! document_route {
    ($name:ident, $path:literal, $index:literal, $summary:literal) => {
        #[utoipa::path(get, path = $path, summary = $summary,
            params(("id" = inline(String), Path, description = "Document id.")),
            responses((status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"), (status = 404, description = "No such document.", body = inline(serde_json::Value), content_type = "application/json"), (status = 502, description = "Elasticsearch failed.", body = String, content_type = "text/plain")), security(("serviceToken" = [])))]
        pub async fn $name(State(state): State<AppState>, Path(id): Path<String>) -> Response { doc(&state, $index, id).await }
    };
}

#[utoipa::path(get, path = "/api/v1/store/{name}/{id}", summary = "One allowlisted store document.",
    params(("name" = inline(String), Path, description = "ml-anomalies, llm-analysis, or agent-campaigns."), ("id" = inline(String), Path, description = "Document id.")),
    responses((status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"), (status = 404, description = "No such document or store.", body = inline(serde_json::Value), content_type = "application/json"), (status = 502, description = "Elasticsearch failed.", body = String, content_type = "text/plain")), security(("serviceToken" = [])))]
pub async fn store_detail(State(state): State<AppState>, Path((name, id)): Path<(String, String)>) -> Response {
    let index = match name.as_str() {
        "ml-anomalies" => "ml-worker-state",
        "llm-analysis" => "llm-worker-state",
        "agent-campaigns" => "agent-campaigns-v1",
        _ => return Ok((StatusCode::NOT_FOUND, Json(Value::Null))),
    };
    doc(&state, index, id).await
}

document_route!(asn, "/api/v1/investigate/asn/{id}", "asn-v1", "One ASN record.");
document_route!(campaign, "/api/v1/investigate/campaign/{id}", "campaigns-v1", "One campaign.");
document_route!(identity, "/api/v1/investigate/identity/{id}", "attackers-v1", "One attacker identity.");
document_route!(session_summary, "/api/v1/investigate/session/{id}/summary", "sessions-v1", "One session summary.");
document_route!(payload_delivery, "/api/v1/payloads/{id}/delivery", "payload-delivery-v1", "One payload delivery record.");
document_route!(replay_detail, "/api/v1/replay/{id}", "cowrie-ttylog-v1", "One replay record.");

#[utoipa::path(get, path = "/api/v1/sources/{ip}/events", summary = "Events from one source.", params(("ip" = inline(String), Path), ("range" = inline(Option<String>), Query)), responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 400, description = "Invalid range.", body = String), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_events(State(state): State<AppState>, Path(ip): Path<String>, Query(query): Query<RangeQuery>) -> Response {
    let range = range(&query)?; source_page(&state, &["events-v1"], json!({"bool":{"filter":[{"term":{"source.ip":validate_id(ip)?}},{"range":{"@timestamp":{"gte":range}}} ]}}), json!([{"@timestamp":{"order":"desc"}}])).await
}

#[utoipa::path(get, path = "/api/v1/sources/{ip}/sessions", summary = "Sessions from one source.", params(("ip" = inline(String), Path), ("range" = inline(Option<String>), Query)), responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 400, description = "Invalid range.", body = String), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_sessions(State(state): State<AppState>, Path(ip): Path<String>, Query(query): Query<RangeQuery>) -> Response {
    let range = range(&query)?; source_page(&state, &["sessions-v1"], json!({"bool":{"filter":[{"term":{"source.ip":validate_id(ip)?}},{"range":{"@timestamp":{"gte":range}}} ]}}), json!([{"@timestamp":{"order":"desc"}}])).await
}

#[utoipa::path(get, path = "/api/v1/sources/{ip}/timeline", summary = "Timeline for one source.", params(("ip" = inline(String), Path), ("range" = inline(Option<String>), Query)), responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 400, description = "Invalid range.", body = String), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_timeline(State(state): State<AppState>, Path(ip): Path<String>, Query(query): Query<RangeQuery>) -> Response {
    let range = range(&query)?; source_page(&state, &["events-v1"], json!({"bool":{"filter":[{"term":{"source.ip":validate_id(ip)?}},{"range":{"@timestamp":{"gte":range}}} ]}}), json!([{"@timestamp":{"order":"asc"}}])).await
}

#[utoipa::path(get, path = "/api/v1/sources/{ip}/network", summary = "Network information for one source.", params(("ip" = inline(String), Path)), responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 404, description = "No such source.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_network(State(state): State<AppState>, Path(ip): Path<String>) -> Response { first(&state, &["network-v1"], json!({"term":{"source.ip":validate_id(ip)?}})).await }

#[utoipa::path(get, path = "/api/v1/sources/{ip}/identities", summary = "Attacker identity for one source.", params(("ip" = inline(String), Path)), responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 404, description = "No such source.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_identities(State(state): State<AppState>, Path(ip): Path<String>) -> Response { first(&state, &["attackers-v1"], json!({"term":{"ips.keyword":validate_id(ip)?}})).await }

#[utoipa::path(get, path = "/api/v1/investigate/blocked-ips", summary = "Blocked IP records.", responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn blocked_ips(State(state): State<AppState>) -> Response { page(&state, &["dashboard-ip-block-v1"], json!({"match_all": {}}), json!([{"BlockedAt":{"order":"desc","unmapped_type":"date"}}])).await }

#[utoipa::path(get, path = "/api/v1/ioc/catalog", summary = "IOC catalog.", responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn ioc_catalog(State(state): State<AppState>) -> Response { page(&state, &["ioc-catalog-v1"], json!({"match_all": {}}), json!([{"@timestamp":{"order":"desc","unmapped_type":"date"}}])).await }

#[utoipa::path(get, path = "/api/v1/ioc/{kind}/{value}", summary = "One IOC.", params(("kind" = inline(String), Path), ("value" = inline(String), Path)), responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 404, description = "No such IOC.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn ioc(State(state): State<AppState>, Path((kind, value)): Path<(String, String)>) -> Response { first(&state, &["ioc-v1"], json!({"bool":{"filter":[{"term":{"kind":validate_id(kind)?}},{"term":{"value":validate_id(value)?}}]}})).await }

#[utoipa::path(get, path = "/api/v1/entities/{id}/timeline", summary = "Timeline for one entity.", params(("id" = inline(String), Path)), responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 404, description = "No such entity.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn entity_timeline(State(state): State<AppState>, Path(id): Path<String>) -> Response { source_page(&state, &["events-v1"], json!({"term":{"entity.id":validate_id(id)?}}), json!([{"@timestamp":{"order":"asc"}}])).await }

#[utoipa::path(get, path = "/api/v1/entities/{id}/related", summary = "Entities related to one entity.", params(("id" = inline(String), Path)), responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 404, description = "No such entity.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn entity_related(State(state): State<AppState>, Path(id): Path<String>) -> Response { source_page(&state, &["correlations-v1"], json!({"term":{"entity.id":validate_id(id)?}}), json!([{"@timestamp":{"order":"desc","unmapped_type":"date"}}])).await }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_ranges_are_bounded() {
        assert_eq!(range(&RangeQuery { range: "24h".into() }).unwrap(), "now-24h");
        assert!(range(&RangeQuery { range: "forever".into() }).is_err());
    }
}
