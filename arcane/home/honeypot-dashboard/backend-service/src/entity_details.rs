//! Detail and drill-down documents that are not covered by the store list routes.
//!
//! Where the data really is (checked against the live cluster, 2026-10-09,
//! #3554): sensor events live in `es::EVENT_INDICES` (`honeypot-v2-*` and the
//! alert families). Nothing writes `events-v1`, `sessions-v1`, `network-v1`,
//! `asn-v1`, `ioc-v1`, `ioc-catalog-v1`, `correlations-v1` or
//! `payload-delivery-v1`, so no handler searches them. Per-entity views are
//! aggregations over the event indices (#3532 added the IOC catalog and detail,
//! entity timeline and related-entity routes the same way; no 501 remains).

use std::net::IpAddr;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    events::{any_of, suricata_noise_exclusion, SESSION_FIELDS},
    AppState,
};

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

fn source_ip(ip: String) -> Result<String, (StatusCode, String)> {
    let ip = ip.trim().to_string();
    ip.parse::<IpAddr>().map(|_| ip).map_err(|_| (StatusCode::BAD_REQUEST, "invalid ip".into()))
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) { (StatusCode::BAD_GATEWAY, error.to_string()) }

async fn doc(state: &AppState, index: &str, id: String) -> Response {
    let id = validate_id(id)?;
    match state.es.get_doc(index, &id).await.map_err(bad_gateway)? {
        Some(doc) => Ok((StatusCode::OK, Json(doc))),
        None => Ok((StatusCode::NOT_FOUND, Json(Value::Null))),
    }
}

/// Single document lookup by a non-id field: 404 when there is no match.
async fn first(state: &AppState, indices: &[&str], query: Value) -> Response {
    let result = state.es.search_index(indices, json!({"size": 1, "query": query})).await.map_err(bad_gateway)?;
    match result["hits"]["hits"].as_array().and_then(|hits| hits.first()) {
        Some(hit) => Ok((StatusCode::OK, Json(hit["_source"].clone()))),
        None => Ok((StatusCode::NOT_FOUND, Json(Value::Null))),
    }
}

/// One page of raw `_source` documents. `total` is exact.
fn list_body(result: &Value) -> Value {
    let rows: Vec<Value> = result["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(|hit| hit["_source"].clone()).collect())
        .unwrap_or_default();
    json!({"total": result["hits"]["total"]["value"].as_u64().unwrap_or(0), "rows": rows})
}

/// Newest-first window reported oldest-first (timeline shape).
fn oldest_first(mut body: Value) -> Value {
    if let Some(rows) = body["rows"].as_array_mut() {
        rows.reverse();
    }
    body
}

/// Lists answer `200 {"total":0,"rows":[]}` when nothing matches (#3554);
/// they never 404.
async fn page(state: &AppState, indices: &[&str], query: Value, sort: Value) -> Response {
    let result = state.es.search_index(indices, json!({"size": 100, "track_total_hits": true, "sort": sort, "query": query})).await.map_err(bad_gateway)?;
    Ok((StatusCode::OK, Json(list_body(&result))))
}

/// Filter every event-level drill-down shares: the scope clause, the same
/// suricata noise exclusion the explorer applies.
fn event_scope(filters: Vec<Value>) -> Value {
    json!({"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}})
}

fn source_scope(ip: &str, range: &str) -> Value {
    event_scope(vec![json!({"term": {"source.ip": ip}}), json!({"range": {"@timestamp": {"gte": range}}})])
}

/// Newest 100 events for the scope. `oldest_first` turns it into a timeline.
fn source_event_body(ip: &str, range: &str) -> Value {
    json!({"size": 100, "track_total_hits": true, "sort": [{"@timestamp": {"order": "desc"}}], "query": source_scope(ip, range)})
}

/// Per-session buckets (honeypot.session, the field the IP profile in
/// investigate.rs aggregates on), newest session first.
fn session_aggs() -> Value {
    json!({
        "sessions": {
            "terms": {"field": "honeypot.session", "size": 100, "order": {"last": "desc"}},
            "aggs": {"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}}
        },
        "session_count": {"cardinality": {"field": "honeypot.session"}}
    })
}

fn session_list(result: &Value) -> Value {
    let rows: Vec<Value> = result["aggregations"]["sessions"]["buckets"]
        .as_array()
        .map(|buckets| buckets.iter().map(|bucket| json!({
            "session": bucket["key"],
            "events": bucket["doc_count"],
            "first": bucket["first"]["value_as_string"],
            "last": bucket["last"]["value_as_string"],
        })).collect())
        .unwrap_or_default();
    json!({"total": result["aggregations"]["session_count"]["value"].as_u64().unwrap_or(0), "rows": rows})
}

/// `[{key, count}]` for a terms aggregation.
fn key_counts(result: &Value, name: &str) -> Vec<Value> {
    result["aggregations"][name]["buckets"]
        .as_array()
        .map(|buckets| buckets.iter().map(|bucket| json!({"key": bucket["key"], "count": bucket["doc_count"]})).collect())
        .unwrap_or_default()
}

/// The single value of a size-1 terms aggregation, or null.
fn top_key(result: &Value, name: &str) -> Value {
    result["aggregations"][name]["buckets"][0]["key"].clone()
}

fn total(result: &Value) -> u64 {
    result["hits"]["total"]["value"].as_u64().unwrap_or(0)
}

fn source_network_body(ip: &str) -> Value {
    json!({
        "size": 0,
        "track_total_hits": true,
        "query": event_scope(vec![json!({"term": {"source.ip": ip}})]),
        "aggs": {
            "asn": {"terms": {"field": "source.as.asn", "size": 1}},
            "organization": {"terms": {"field": "source.as.organization_name", "size": 1}},
            "provider": {"terms": {"field": "source.as.type", "size": 1}},
            "country": {"terms": {"field": "source.geo.country_iso_code", "size": 1}}
        }
    })
}

fn asn_body(asn: i64) -> Value {
    json!({
        "size": 0,
        "track_total_hits": true,
        "query": event_scope(vec![json!({"term": {"source.as.asn": asn}})]),
        "aggs": {
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
            "organization": {"terms": {"field": "source.as.organization_name", "size": 1}},
            "provider": {"terms": {"field": "source.as.type", "size": 1}},
            "sources": {"terms": {"field": "source.ip", "size": 50}},
            "source_count": {"cardinality": {"field": "source.ip"}}
        }
    })
}

fn session_summary_body(id: &str) -> Value {
    json!({
        "size": 0,
        "track_total_hits": true,
        "query": event_scope(vec![any_of(SESSION_FIELDS, id)]),
        "aggs": {
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
            "sensors": {"terms": {"field": "event.sensor", "size": 20}},
            "commands": {"terms": {"field": "honeypot.canonical_command", "size": 50}},
            "sources": {"terms": {"field": "source.ip", "size": 20}}
        }
    })
}

/// Payload delivery is keyed on `honeypot.canonical_shasum`, the field the
/// IP profile's "payloads" aggregation and the payload cluster use. Plain
/// `honeypot.shasum` also carries TTY-recording hashes (events.rs `shasum`).
fn payload_delivery_body(hash: &str) -> Value {
    let mut aggs = session_aggs();
    aggs["sources"] = json!({"terms": {"field": "source.ip", "size": 50}});
    json!({
        "size": 100,
        "track_total_hits": true,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": event_scope(vec![json!({"term": {"honeypot.canonical_shasum": hash}})]),
        "aggs": aggs
    })
}

fn asn_number(id: &str) -> Result<i64, (StatusCode, String)> {
    id.trim().trim_start_matches("AS").parse::<i64>().map_err(|_| (StatusCode::BAD_REQUEST, "invalid asn".into()))
}

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

// campaigns-v1 is written by campaign_correlator; it is empty on a fresh
// cluster, so "no such campaign" is a 404 and an index error is a 502.
document_route!(campaign, "/api/v1/investigate/campaign/{id}", "campaigns-v1", "One campaign.");
// attackers-v1 documents are looked up by document id here.
document_route!(identity, "/api/v1/investigate/identity/{id}", "attackers-v1", "One attacker identity.");
document_route!(replay_detail, "/api/v1/replay/{id}", "cowrie-ttylog-v1", "One replay record.");

#[utoipa::path(get, path = "/api/v1/sources/{ip}/events", summary = "Newest events from one source.", params(("ip" = inline(String), Path, description = "Source IPv4 or IPv6 address."), ("range" = inline(Option<String>), Query, description = "1h, 6h, 24h (default), 7d or 30d.")), responses((status = 200, description = "Page of raw event documents from EVENT_INDICES, newest first, at most 100. Nothing in range is {\"total\":0,\"rows\":[]}.", body = inline(serde_json::Value)), (status = 400, description = "Invalid ip or range.", body = String), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_events(State(state): State<AppState>, Path(ip): Path<String>, Query(query): Query<RangeQuery>) -> Response {
    let (ip, range) = (source_ip(ip)?, range(&query)?);
    let result = state.es.search(source_event_body(&ip, &range)).await.map_err(bad_gateway)?;
    Ok((StatusCode::OK, Json(list_body(&result))))
}

#[utoipa::path(get, path = "/api/v1/sources/{ip}/sessions", summary = "Sessions from one source, aggregated from its events.", params(("ip" = inline(String), Path, description = "Source IPv4 or IPv6 address."), ("range" = inline(Option<String>), Query, description = "1h, 6h, 24h (default), 7d or 30d.")), responses((status = 200, description = "{total: distinct sessions, rows: [{session, events, first, last}]}, newest session first. Nothing in range is {\"total\":0,\"rows\":[]}.", body = inline(serde_json::Value)), (status = 400, description = "Invalid ip or range.", body = String), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_sessions(State(state): State<AppState>, Path(ip): Path<String>, Query(query): Query<RangeQuery>) -> Response {
    let (ip, range) = (source_ip(ip)?, range(&query)?);
    let body = json!({"size": 0, "query": source_scope(&ip, &range), "aggs": session_aggs()});
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    Ok((StatusCode::OK, Json(session_list(&result))))
}

#[utoipa::path(get, path = "/api/v1/sources/{ip}/timeline", summary = "Timeline for one source.", params(("ip" = inline(String), Path, description = "Source IPv4 or IPv6 address."), ("range" = inline(Option<String>), Query, description = "1h, 6h, 24h (default), 7d or 30d.")), responses((status = 200, description = "Page of raw event documents: the newest 100 in range, oldest first. Nothing in range is {\"total\":0,\"rows\":[]}.", body = inline(serde_json::Value)), (status = 400, description = "Invalid ip or range.", body = String), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_timeline(State(state): State<AppState>, Path(ip): Path<String>, Query(query): Query<RangeQuery>) -> Response {
    let (ip, range) = (source_ip(ip)?, range(&query)?);
    let result = state.es.search(source_event_body(&ip, &range)).await.map_err(bad_gateway)?;
    Ok((StatusCode::OK, Json(oldest_first(list_body(&result)))))
}

#[utoipa::path(get, path = "/api/v1/sources/{ip}/network", summary = "ASN, organization, provider and country for one source.", params(("ip" = inline(String), Path, description = "Source IPv4 or IPv6 address.")), responses((status = 200, description = "{ip, asn, organization, provider, country, events}, read from the source.as.* and source.geo.* fields of its events.", body = inline(serde_json::Value)), (status = 400, description = "Invalid ip.", body = String), (status = 404, description = "No events from this source.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_network(State(state): State<AppState>, Path(ip): Path<String>) -> Response {
    let ip = source_ip(ip)?;
    let result = state.es.search(source_network_body(&ip)).await.map_err(bad_gateway)?;
    if total(&result) == 0 {
        return Ok((StatusCode::NOT_FOUND, Json(Value::Null)));
    }
    Ok((StatusCode::OK, Json(json!({
        "ip": ip,
        "asn": top_key(&result, "asn"),
        "organization": top_key(&result, "organization"),
        "provider": top_key(&result, "provider"),
        "country": top_key(&result, "country"),
        "events": total(&result),
    }))))
}

#[utoipa::path(get, path = "/api/v1/sources/{ip}/identities", summary = "Attacker identity for one source.", params(("ip" = inline(String), Path)), responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 404, description = "No such source.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_identities(State(state): State<AppState>, Path(ip): Path<String>) -> Response { first(&state, &["attackers-v1"], json!({"term":{"ips.keyword":validate_id(ip)?}})).await }

#[utoipa::path(get, path = "/api/v1/investigate/blocked-ips", summary = "Blocked IP records.", responses((status = 200, description = "{total, rows} of dashboard-ip-block-v1 records, newest block first. No blocks yet is {\"total\":0,\"rows\":[]}.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn blocked_ips(State(state): State<AppState>) -> Response { page(&state, &["dashboard-ip-block-v1"], json!({"match_all": {}}), json!([{"BlockedAt":{"order":"desc","unmapped_type":"date"}}])).await }

// ---------------------------------------------------------------------------
// #3532: IOC catalog, IOC detail, entity timeline and related entities.
//
// None of these has a producer of its own. Every answer is an aggregation or
// a query over data that already exists (`es::EVENT_INDICES`, `attackers-v1`,
// `campaigns-v1`, `flow-links-v1`, `ml-anomalies`, `llm-analysis`), shaped
// for a thin typed adapter: snake_case keys, no raw `_source` dumps.
//
// Observed on the live cluster (2026-10-09, read-only):
// - `honeypot` is a `flattened` field, so `honeypot.*` terms work but carry
//   no sub-field mapping; Suricata strings are `text` with a `.keyword`
//   sub-field, and only the `.keyword` form aggregates.
// - Suricata writes CVE ids as `CVE_2025_29927`; the honeypots write
//   `CVE-2026-24061`. Both are served as the dashed form.
// - Many cowrie rows carry only `honeypot.src_ip` and no `source.ip`, so an
//   address scope also matches `honeypot.src_ip` when `source.ip` is absent.
// ---------------------------------------------------------------------------

/// Source ranges that are the fleet's own, by shape (the same shapes
/// `events::is_fleet_address` recognises), as ES `terms` CIDR values.
const FLEET_CIDRS: &[&str] = &[
    "127.0.0.0/8", "0.0.0.0/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "::1/128", "::/128", "fc00::/7", "fe80::/10",
];

/// Event-scope `must_not` clauses that keep the fleet out of every IOC and
/// related-entity answer: a row whose `source.ip` is in a fleet range or in
/// the deployment's `HONEYPOT_SELF_IPS` is the fleet talking to itself.
///
/// A row with no `source.ip` whose fallback address (`honeypot.src_ip`, the
/// nested dionaea peer) is the tunnel peer is kept: it is an attacker the
/// enrichment could not resolve (3,050 dionaea captures of one payload in
/// 30 days are like this), and dropping it would lose the indicator. It is
/// counted as evidence, never listed as a source: see `fallback_excluding`.
fn fleet_exclusion() -> Vec<Value> {
    let mut addresses: Vec<String> = FLEET_CIDRS.iter().map(|cidr| cidr.to_string()).collect();
    addresses.extend(crate::dashboard::self_addresses());
    vec![json!({"terms": {"source.ip": addresses}})]
}

/// Where an attacker address lives when the row has no `source.ip`: the
/// sensor's own field (many cowrie rows) and the nested dionaea peer.
/// `events::attacker_ip` reads the same fields.
const FALLBACK_ADDRESS_FIELDS: &[&str] = &["honeypot.src_ip", "honeypot.data.connection.remote_ip"];

/// Distinct-address sub-aggregations: `source.ip`, plus the fallback fields on
/// rows without one, minus the fleet's own addresses. The total is the largest
/// of them (a lower bound).
fn source_card_aggs() -> Vec<(String, Value)> {
    let own = crate::dashboard::self_addresses();
    let fallback: serde_json::Map<String, Value> = FALLBACK_ADDRESS_FIELDS
        .iter()
        .enumerate()
        .map(|(index, field)| {
            (format!("f{index}"), json!({"filter": {"bool": {"must_not": [{"terms": {*field: own}}]}}, "aggs": {"v": {"cardinality": {"field": field}}}}))
        })
        .collect();
    vec![
        ("sources".into(), json!({"cardinality": {"field": "source.ip"}})),
        ("sources_fb".into(), json!({"filter": {"bool": {"must_not": [{"exists": {"field": "source.ip"}}]}}, "aggs": fallback})),
    ]
}

fn source_total(parent: &Value) -> u64 {
    let mut best = parent["sources"]["value"].as_u64().unwrap_or(0);
    for index in 0..FALLBACK_ADDRESS_FIELDS.len() {
        best = best.max(parent["sources_fb"][format!("f{index}")]["v"]["value"].as_u64().unwrap_or(0));
    }
    best
}

/// Top-address aggregations named `name` and `name_fb`, merged by
/// `merged_sources`. The fallback terms leave the fleet's own addresses out.
fn source_terms_aggs(name: &str, size: u64) -> Vec<(String, Value)> {
    let own = crate::dashboard::self_addresses();
    let fallback: serde_json::Map<String, Value> = FALLBACK_ADDRESS_FIELDS
        .iter()
        .enumerate()
        .map(|(index, field)| (format!("f{index}"), json!({"terms": {"field": field, "size": size, "exclude": own}})))
        .collect();
    vec![
        (name.to_string(), json!({"terms": {"field": "source.ip", "size": size}})),
        (format!("{name}_fb"), json!({"filter": {"bool": {"must_not": [{"exists": {"field": "source.ip"}}]}}, "aggs": fallback})),
    ]
}

/// `(address, events)` from `source_terms_aggs` results under `parent`
/// (a response's `aggregations`, or a bucket), summed across the sources,
/// busiest first, at most `size`.
fn merged_sources(parent: &Value, name: &str, size: usize) -> Vec<(String, u64)> {
    let mut counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut add = |node: &Value| {
        for bucket in node["buckets"].as_array().into_iter().flatten() {
            if let Some(ip) = bucket["key"].as_str().filter(|ip| !ip.is_empty()) {
                *counts.entry(ip.to_string()).or_default() += bucket["doc_count"].as_u64().unwrap_or(0);
            }
        }
    };
    add(&parent[name]);
    for index in 0..FALLBACK_ADDRESS_FIELDS.len() {
        add(&parent[format!("{name}_fb")][format!("f{index}")]);
    }
    let mut rows: Vec<(String, u64)> = counts.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(size);
    rows
}

/// `src_ip` exclusion for the ML and LLM stores, whose address field is
/// `src_ip` (type `ip`).
fn fleet_store_exclusion() -> Value {
    let mut addresses: Vec<String> = FLEET_CIDRS.iter().map(|cidr| cidr.to_string()).collect();
    addresses.extend(crate::dashboard::self_addresses());
    json!({"terms": {"src_ip": addresses}})
}

/// The shared query: every filter, minus the explorer's noise, the fleet's own
/// traffic, and `extra_must_not`.
fn ioc_scope(filters: Vec<Value>, extra_must_not: Vec<Value>) -> Value {
    let mut must_not = suricata_noise_exclusion().as_array().cloned().unwrap_or_default();
    must_not.extend(fleet_exclusion());
    must_not.extend(extra_must_not);
    json!({"bool": {"filter": filters, "must_not": must_not}})
}

fn time_range(range: &str) -> Value {
    json!({"range": {"@timestamp": {"gte": range}}})
}

/// `now-<window>` for an optional `range` parameter, falling back to
/// `default` when absent. Only the windows the other routes accept.
fn range_or(value: &Option<String>, default: &str) -> Result<String, (StatusCode, String)> {
    range(&RangeQuery { range: value.clone().unwrap_or_else(|| default.to_string()) })
}

/// A secret-bearing indicator never reads from the sensors `secrets_boundary`
/// scrubs: their stored passwords are historical plaintext the API must not
/// return (#3213), so those rows are not counted either.
fn secret_exclusion() -> Vec<Value> {
    vec![json!({"terms": {"event.sensor": crate::secrets_boundary::CREDENTIAL_SENSORS}})]
}

struct IocField {
    path: &'static str,
    /// Restrict the field to these sensors; empty means any document with it.
    sensors: &'static [&'static str],
    /// Leave out rows whose `canonical_fingerprint_kind` is one of these.
    except_fingerprint_kinds: &'static [&'static str],
}

enum IocShape {
    Fields(&'static [IocField]),
    /// A `user:password` pair over `canonical_user` and `canonical_pass`.
    Credential,
}

struct IocKindDef {
    name: &'static str,
    shape: IocShape,
    /// The indicator is (or contains) a secret: scrubbed sensors are excluded.
    secret: bool,
}

/// A protocol banner every client of the protocol sends (RFB 003.008) is not
/// an indicator of anything; JA3/JA4/HASSH, SSH keys and User-Agents are.
const BANNER_KINDS: &[&str] = &["client banner"];

const USER_FIELD: &str = "honeypot.canonical_user";
const PASS_FIELD: &str = "honeypot.canonical_pass";

/// The ten kinds the dashboard hub knows. Field choice is deliberate: each
/// is the `canonical_*` promotion the explorer pivots use, or the
/// producer-specific field when there is no promotion.
const IOC_KINDS: &[IocKindDef] = &[
    IocKindDef { name: "hash", shape: IocShape::Fields(&[IocField { path: "honeypot.canonical_shasum", sensors: &[], except_fingerprint_kinds: &[] }]), secret: false },
    IocKindDef { name: "domain", shape: IocShape::Fields(&[IocField { path: "honeypot.query", sensors: &["dns-honeypot"], except_fingerprint_kinds: &[] }]), secret: false },
    IocKindDef { name: "url", shape: IocShape::Fields(&[IocField { path: "honeypot.url", sensors: &[], except_fingerprint_kinds: &[] }]), secret: false },
    IocKindDef { name: "credential", shape: IocShape::Credential, secret: true },
    IocKindDef { name: "command", shape: IocShape::Fields(&[IocField { path: "honeypot.canonical_command", sensors: &[], except_fingerprint_kinds: &[] }]), secret: false },
    IocKindDef { name: "fingerprint", shape: IocShape::Fields(&[IocField { path: "honeypot.canonical_fingerprint", sensors: &[], except_fingerprint_kinds: BANNER_KINDS }]), secret: false },
    IocKindDef {
        name: "cve",
        shape: IocShape::Fields(&[
            IocField { path: "honeypot.cve", sensors: &[], except_fingerprint_kinds: &[] },
            IocField { path: "suricata.eve.alert.metadata.cve.keyword", sensors: &[], except_fingerprint_kinds: &[] },
        ]),
        secret: false,
    },
    IocKindDef { name: "signature", shape: IocShape::Fields(&[IocField { path: "suricata.eve.alert.signature.keyword", sensors: &[], except_fingerprint_kinds: &[] }]), secret: false },
    IocKindDef { name: "username", shape: IocShape::Fields(&[IocField { path: USER_FIELD, sensors: &[], except_fingerprint_kinds: &[] }]), secret: false },
    IocKindDef { name: "password", shape: IocShape::Fields(&[IocField { path: PASS_FIELD, sensors: &[], except_fingerprint_kinds: &[] }]), secret: true },
];

fn ioc_kind(name: &str) -> Option<&'static IocKindDef> {
    IOC_KINDS.iter().find(|def| def.name == name)
}

/// `CVE_2025_29927` and `cve-2025-29927` both become `CVE-2025-29927`.
fn normalize_cve(value: &str) -> String {
    value.trim().replace('_', "-").to_uppercase()
}

/// The stored spellings a CVE id can have: dashed (honeypots) and underscored
/// (Suricata).
fn cve_variants(value: &str) -> Vec<String> {
    let dashed = normalize_cve(value);
    let underscored = dashed.replace('-', "_");
    vec![dashed, underscored]
}

/// ES wildcard syntax: escape the three metacharacters.
fn wildcard_escape(text: &str) -> String {
    text.chars().fold(String::new(), |mut out, c| {
        if matches!(c, '*' | '?' | '\\') {
            out.push('\\');
        }
        out.push(c);
        out
    })
}

fn wildcard(path: &str, text: &str) -> Value {
    json!({"wildcard": {path: {"value": format!("*{}*", wildcard_escape(text)), "case_insensitive": true}}})
}

fn field_presence(field: &IocField) -> Vec<Value> {
    let mut filters = vec![json!({"exists": {"field": field.path}})];
    if !field.sensors.is_empty() {
        filters.push(json!({"terms": {"event.sensor": field.sensors}}));
    }
    filters
}

fn field_exceptions(field: &IocField) -> Vec<Value> {
    if field.except_fingerprint_kinds.is_empty() {
        vec![]
    } else {
        vec![json!({"terms": {"honeypot.canonical_fingerprint_kind": field.except_fingerprint_kinds}})]
    }
}

/// Per-field statistics every IOC bucket carries.
fn ioc_stats() -> Value {
    let mut stats = json!({
        "first": {"min": {"field": "@timestamp"}},
        "last": {"max": {"field": "@timestamp"}},
        "sessions": {"cardinality": {"field": "honeypot.session"}}
    });
    for (name, agg) in source_card_aggs() {
        stats[name] = agg;
    }
    stats
}

/// The `(aggregation name, aggregation)` pairs for one kind. A kind with two
/// fields (cve) yields two; their buckets are merged by value on the way out.
fn catalog_aggs(def: &IocKindDef, q: Option<&str>, size: u64) -> Vec<(String, Value)> {
    let secret = if def.secret { secret_exclusion() } else { vec![] };
    match &def.shape {
        IocShape::Fields(fields) => fields
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let mut filters = field_presence(field);
                if let Some(q) = q {
                    filters.push(wildcard(field.path, q));
                }
                let mut must_not = secret.clone();
                must_not.extend(field_exceptions(field));
                let agg = json!({
                    "filter": {"bool": {"filter": filters, "must_not": must_not}},
                    "aggs": {"v": {"terms": {"field": field.path, "size": size}, "aggs": ioc_stats()}}
                });
                (format!("{}__{}", def.name, index), agg)
            })
            .collect(),
        IocShape::Credential => {
            let mut filters = vec![json!({"bool": {"should": [{"exists": {"field": USER_FIELD}}, {"exists": {"field": PASS_FIELD}}], "minimum_should_match": 1}})];
            if let Some(q) = q {
                filters.push(json!({"bool": {"should": [wildcard(USER_FIELD, q), wildcard(PASS_FIELD, q)], "minimum_should_match": 1}}));
            }
            let agg = json!({
                "filter": {"bool": {"filter": filters, "must_not": secret}},
                "aggs": {"v": {
                    "multi_terms": {"terms": [{"field": USER_FIELD, "missing": ""}, {"field": PASS_FIELD, "missing": ""}], "size": size},
                    "aggs": ioc_stats()
                }}
            });
            vec![(format!("{}__0", def.name), agg)]
        }
    }
}

fn catalog_body(range: &str, defs: &[&IocKindDef], q: Option<&str>, size: u64) -> Value {
    let mut aggs = serde_json::Map::new();
    for def in defs {
        for (name, agg) in catalog_aggs(def, q, size) {
            aggs.insert(name, agg);
        }
    }
    json!({"size": 0, "track_total_hits": false, "query": ioc_scope(vec![time_range(range)], vec![]), "aggs": aggs})
}

/// One indicator row. `id` is `kind:value`, the id format `/ioc/{kind}/{value}`
/// and the `ioc:` entity id both use.
#[derive(Clone, Debug, PartialEq)]
struct IocRow {
    kind: &'static str,
    value: String,
    events: u64,
    sources: u64,
    sessions: u64,
    first_seen: Option<String>,
    last_seen: Option<String>,
}

impl IocRow {
    fn to_json(&self) -> Value {
        json!({
            "id": format!("{}:{}", self.kind, self.value),
            "kind": self.kind,
            "value": self.value,
            "events": self.events,
            "sources": self.sources,
            "sessions": self.sessions,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        })
    }
}

fn bucket_value(def: &IocKindDef, bucket: &Value) -> Option<String> {
    let raw = match &def.shape {
        IocShape::Credential => {
            let parts = bucket["key"].as_array()?;
            let user = parts.first().and_then(Value::as_str).unwrap_or("");
            let pass = parts.get(1).and_then(Value::as_str).unwrap_or("");
            if user.is_empty() && pass.is_empty() {
                return None;
            }
            format!("{user}:{pass}")
        }
        IocShape::Fields(_) => match &bucket["key"] {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        },
    };
    if raw.is_empty() {
        return None;
    }
    Some(if def.name == "cve" { normalize_cve(&raw) } else { raw })
}

fn merge_seen(current: Option<String>, other: Option<String>, keep_earlier: bool) -> Option<String> {
    match (current, other) {
        (Some(a), Some(b)) => Some(if (a <= b) == keep_earlier { a } else { b }),
        (a, b) => a.or(b),
    }
}

/// Rows for one kind from a catalog response: buckets of every field merged
/// by value (events add; sources and sessions take the larger count, a lower
/// bound where one value spans two fields), busiest first, at most `size`.
/// The flag is true when ES reported buckets beyond the requested size.
fn catalog_rows(result: &Value, def: &'static IocKindDef, size: usize) -> (Vec<IocRow>, bool) {
    let mut merged: std::collections::HashMap<String, IocRow> = std::collections::HashMap::new();
    let mut truncated = false;
    for index in 0..4 {
        let node = &result["aggregations"][format!("{}__{}", def.name, index)]["v"];
        let Some(buckets) = node["buckets"].as_array() else { continue };
        truncated |= node["sum_other_doc_count"].as_u64().unwrap_or(0) > 0;
        for bucket in buckets {
            let Some(value) = bucket_value(def, bucket) else { continue };
            let row = IocRow {
                kind: def.name,
                value: value.clone(),
                events: bucket["doc_count"].as_u64().unwrap_or(0),
                sources: source_total(bucket),
                sessions: bucket["sessions"]["value"].as_u64().unwrap_or(0),
                first_seen: bucket["first"]["value_as_string"].as_str().map(String::from),
                last_seen: bucket["last"]["value_as_string"].as_str().map(String::from),
            };
            merged
                .entry(value)
                .and_modify(|existing| {
                    existing.events += row.events;
                    existing.sources = existing.sources.max(row.sources);
                    existing.sessions = existing.sessions.max(row.sessions);
                    existing.first_seen = merge_seen(existing.first_seen.take(), row.first_seen.clone(), true);
                    existing.last_seen = merge_seen(existing.last_seen.take(), row.last_seen.clone(), false);
                })
                .or_insert(row);
        }
    }
    let mut rows: Vec<IocRow> = merged.into_values().collect();
    rows.sort_by(|a, b| b.events.cmp(&a.events).then_with(|| a.value.cmp(&b.value)));
    if rows.len() > size {
        truncated = true;
        rows.truncate(size);
    }
    (rows, truncated)
}

const CATALOG_MAX_SIZE: u64 = 100;
const CATALOG_DEFAULT_SIZE: u64 = 25;

#[derive(Deserialize)]
pub struct IocCatalogQuery {
    pub kind: Option<String>,
    pub q: Option<String>,
    pub size: Option<u64>,
    pub range: Option<String>,
}

#[derive(Deserialize)]
pub struct IocDetailQuery {
    pub range: Option<String>,
}

#[derive(Deserialize)]
pub struct TimelineQuery {
    pub range: Option<String>,
    pub limit: Option<u64>,
}

#[derive(Deserialize)]
pub struct RelatedQuery {
    pub range: Option<String>,
}

fn catalog_response(result: &Value, defs: &[&'static IocKindDef], range: &str, size: u64) -> Value {
    let mut kinds = serde_json::Map::new();
    let mut truncated = Vec::new();
    for def in IOC_KINDS {
        if !defs.iter().any(|selected| selected.name == def.name) {
            kinds.insert(def.name.to_string(), json!([]));
            continue;
        }
        let (rows, cut) = catalog_rows(result, def, size as usize);
        if cut {
            truncated.push(def.name);
        }
        kinds.insert(def.name.to_string(), Value::Array(rows.iter().map(IocRow::to_json).collect()));
    }
    json!({"range": range.trim_start_matches("now-"), "size": size, "kinds": kinds, "truncated": truncated})
}

/// The clause matching one indicator value, or `Err` when the value cannot be
/// that kind (an empty credential).
fn ioc_value_clause(def: &IocKindDef, value: &str) -> Result<Value, (StatusCode, String)> {
    match &def.shape {
        IocShape::Credential => {
            let (user, pass) = value.split_once(':').unwrap_or((value, ""));
            if user.is_empty() && pass.is_empty() {
                return Err((StatusCode::BAD_REQUEST, "credential must be user:password".into()));
            }
            let side = |path: &str, text: &str| -> Value {
                if text.is_empty() {
                    json!({"bool": {"should": [{"term": {path: ""}}, {"bool": {"must_not": [{"exists": {"field": path}}]}}], "minimum_should_match": 1}})
                } else {
                    json!({"term": {path: text}})
                }
            };
            Ok(json!({"bool": {"filter": [side(USER_FIELD, user), side(PASS_FIELD, pass)]}}))
        }
        IocShape::Fields(fields) => {
            let should: Vec<Value> = fields
                .iter()
                .map(|field| {
                    let matcher = if def.name == "cve" {
                        json!({"terms": {field.path: cve_variants(value)}})
                    } else {
                        json!({"term": {field.path: value}})
                    };
                    if field.sensors.is_empty() && field.except_fingerprint_kinds.is_empty() {
                        matcher
                    } else {
                        let mut filters = vec![matcher];
                        if !field.sensors.is_empty() {
                            filters.push(json!({"terms": {"event.sensor": field.sensors}}));
                        }
                        json!({"bool": {"filter": filters, "must_not": field_exceptions(field)}})
                    }
                })
                .collect();
            Ok(json!({"bool": {"should": should, "minimum_should_match": 1}}))
        }
    }
}

fn ioc_extra_must_not(def: &IocKindDef) -> Vec<Value> {
    if def.secret { secret_exclusion() } else { vec![] }
}

const IOC_RECENT_EVENTS: u64 = 20;
const IOC_LIST_SIZE: u64 = 20;

fn ioc_detail_body(def: &IocKindDef, value: &str, range: &str) -> Result<Value, (StatusCode, String)> {
    let clause = ioc_value_clause(def, value)?;
    let mut body = json!({
        "size": IOC_RECENT_EVENTS,
        "track_total_hits": true,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": ioc_scope(vec![time_range(range), clause], ioc_extra_must_not(def)),
        "aggs": {
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
            "sensors": {"terms": {"field": "event.sensor", "size": 20}},
            "SOURCE_AGGS": null,
            "sessions": {
                "terms": {"field": "honeypot.session", "size": IOC_LIST_SIZE, "order": {"last": "desc"}},
                "aggs": {"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}}
            },
            "session_count": {"cardinality": {"field": "honeypot.session"}},
            "payloads": {"terms": {"field": "honeypot.canonical_shasum", "size": 10}}
        }
    });
    let aggs = body["aggs"].as_object_mut().expect("aggs object");
    aggs.remove("SOURCE_AGGS");
    for (name, agg) in source_terms_aggs("sources", IOC_LIST_SIZE).into_iter().chain(source_card_aggs().into_iter().map(|(n, a)| (format!("count_{n}"), a))) {
        aggs.insert(name, agg);
    }
    Ok(body)
}

/// Every field a session id of any sensor can live in, as one OR clause.
fn sessions_any(ids: &[String]) -> Value {
    let should: Vec<Value> = SESSION_FIELDS.iter().map(|field| json!({"terms": {*field: ids}})).collect();
    json!({"bool": {"should": should, "minimum_should_match": 1}})
}

/// Payload hashes seen in the given sessions: the download that the matching
/// event (a command, a login) belongs to is a different row of the session.
fn session_payloads_body(sessions: &[String], range: &str) -> Value {
    json!({
        "size": 0,
        "track_total_hits": false,
        "query": ioc_scope(vec![time_range(range), sessions_any(sessions)], vec![]),
        "aggs": {"payloads": {"terms": {"field": "honeypot.canonical_shasum", "size": 10}}}
    })
}

/// A compact event, built from the normalized row so the secrets boundary
/// (`secrets_boundary::scrub_source`) has already applied to `detail`.
fn event_summary(hit: &Value) -> Value {
    let row = crate::events::row_from_source(&hit["_source"]);
    json!({
        "id": hit["_id"],
        "time": row.time,
        "sensor": row.sensor,
        "src_ip": row.src_ip,
        "country": row.country,
        "kind": row.kind,
        "proto": row.proto,
        "detail": row.detail,
        "session": row.session,
    })
}

/// Distinct addresses for the detail response, from the `count_`-prefixed
/// cardinality aggregations.
fn detail_source_total(aggregations: &Value) -> u64 {
    let mut best = aggregations["count_sources"]["value"].as_u64().unwrap_or(0);
    for index in 0..FALLBACK_ADDRESS_FIELDS.len() {
        best = best.max(aggregations["count_sources_fb"][format!("f{index}")]["v"]["value"].as_u64().unwrap_or(0));
    }
    best
}

fn ioc_detail_response(def: &IocKindDef, value: &str, range: &str, result: &Value, payloads: Vec<Value>) -> Value {
    let recent: Vec<Value> = result["hits"]["hits"].as_array().map(|hits| hits.iter().map(event_summary).collect()).unwrap_or_default();
    json!({
        "id": format!("{}:{}", def.name, value),
        "kind": def.name,
        "value": value,
        "range": range.trim_start_matches("now-"),
        "events": total(result),
        "first_seen": result["aggregations"]["first"]["value_as_string"],
        "last_seen": result["aggregations"]["last"]["value_as_string"],
        "sources_total": detail_source_total(&result["aggregations"]),
        "sessions_total": result["aggregations"]["session_count"]["value"].as_u64().unwrap_or(0),
        "sensors": key_counts(result, "sensors"),
        "sources": merged_sources(&result["aggregations"], "sources", IOC_LIST_SIZE as usize).into_iter().map(|(key, count)| json!({"key": key, "count": count})).collect::<Vec<_>>(),
        "sessions": session_list(&json!({"aggregations": {"sessions": result["aggregations"]["sessions"], "session_count": result["aggregations"]["session_count"]}}))["rows"],
        "payloads": payloads,
        "recent_events": recent,
    })
}

#[utoipa::path(get, path = "/api/v1/ioc/catalog", summary = "Indicators seen, by kind, aggregated from the event indices.",
    params(
        ("kind" = inline(Option<String>), Query, description = "Only this kind: hash, domain, url, credential, command, fingerprint, cve, signature, username or password. Default all ten."),
        ("q" = inline(Option<String>), Query, description = "Case-insensitive substring filter on the indicator value."),
        ("size" = inline(Option<u64>), Query, description = "Values per kind, 1-100 (default 25)."),
        ("range" = inline(Option<String>), Query, description = "1h, 6h, 24h, 7d (default) or 30d.")
    ),
    responses(
        (status = 200, description = "{range, size, kinds: {<kind>: [{id, kind, value, events, sources, sessions, first_seen, last_seen}]}, truncated: [kind]}, busiest value first. Every kind is present (empty list when nothing was seen); `truncated` names kinds with more values than `size`. `sources` counts distinct source.ip. Credential values are `user:password` (password-only is `:password`); sensors whose stored passwords are scrubbed (http-honeypot, cisco-asa-honeypot) are excluded from credential and password rows. Fleet addresses are excluded.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Unknown kind, bad size or bad range.", body = String),
        (status = 502, description = "Elasticsearch failed.", body = String)
    ), security(("serviceToken" = [])))]
pub async fn ioc_catalog(State(state): State<AppState>, Query(query): Query<IocCatalogQuery>) -> Response {
    let range = range_or(&query.range, "7d")?;
    let size = query.size.unwrap_or(CATALOG_DEFAULT_SIZE);
    if size == 0 || size > CATALOG_MAX_SIZE {
        return Err((StatusCode::BAD_REQUEST, format!("size must be 1-{CATALOG_MAX_SIZE}")));
    }
    let defs: Vec<&'static IocKindDef> = match query.kind.as_deref().map(str::trim).filter(|kind| !kind.is_empty()) {
        Some(kind) => vec![ioc_kind(kind).ok_or((StatusCode::BAD_REQUEST, format!("unknown ioc kind '{kind}'")))?],
        None => IOC_KINDS.iter().collect(),
    };
    let q = query.q.as_deref().map(str::trim).filter(|q| !q.is_empty());
    if q.is_some_and(|q| q.len() > 256) {
        return Err((StatusCode::BAD_REQUEST, "q too long".into()));
    }
    let result = state.es.search(catalog_body(&range, &defs, q, size)).await.map_err(bad_gateway)?;
    Ok((StatusCode::OK, Json(catalog_response(&result, &defs, &range, size))))
}

#[utoipa::path(get, path = "/api/v1/ioc/{kind}/{value}", summary = "One indicator: counts, sensors, top sources, sessions, payloads and recent events.",
    params(
        ("kind" = inline(String), Path, description = "hash, domain, url, credential, command, fingerprint, cve, signature, username or password."),
        ("value" = inline(String), Path, description = "The indicator value, URL-encoded. A credential is user:password."),
        ("range" = inline(Option<String>), Query, description = "1h, 6h, 24h, 7d or 30d (default).")
    ),
    responses(
        (status = 200, description = "{id, kind, value, range, events, first_seen, last_seen, sources_total, sessions_total, sensors: [{key, count}], sources: [{key, count}] (top 20), sessions: [{session, events, first, last}] (newest 20), payloads: [{key, count}] (canonical_shasum in the matching events and, for other kinds, in the matching sessions), recent_events: [{id, time, sensor, src_ip, country, kind, proto, detail, session}] (newest 20)}.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Unknown kind, malformed value or bad range.", body = String),
        (status = 404, description = "The indicator was not seen in range.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch failed.", body = String)
    ), security(("serviceToken" = [])))]
pub async fn ioc(State(state): State<AppState>, Path((kind, value)): Path<(String, String)>, Query(query): Query<IocDetailQuery>) -> Response {
    let range = range_or(&query.range, "30d")?;
    let def = ioc_kind(kind.trim()).ok_or((StatusCode::BAD_REQUEST, format!("unknown ioc kind '{kind}'")))?;
    let value = value.trim().to_string();
    if value.is_empty() || value.len() > 2048 {
        return Err((StatusCode::BAD_REQUEST, "invalid value".into()));
    }
    let value = if def.name == "cve" { normalize_cve(&value) } else { value };
    let result = state.es.search(ioc_detail_body(def, &value, &range)?).await.map_err(bad_gateway)?;
    if total(&result) == 0 {
        return Ok((StatusCode::NOT_FOUND, Json(Value::Null)));
    }
    let payloads = if def.name == "hash" {
        vec![json!({"key": value, "count": total(&result)})]
    } else if !key_counts(&result, "payloads").is_empty() {
        key_counts(&result, "payloads")
    } else {
        let sessions: Vec<String> = session_ids(&result);
        if sessions.is_empty() {
            vec![]
        } else {
            let related = state.es.search(session_payloads_body(&sessions, &range)).await.map_err(bad_gateway)?;
            key_counts(&related, "payloads")
        }
    };
    Ok((StatusCode::OK, Json(ioc_detail_response(def, &value, &range, &result, payloads))))
}

fn session_ids(result: &Value) -> Vec<String> {
    result["aggregations"]["sessions"]["buckets"]
        .as_array()
        .map(|buckets| buckets.iter().filter_map(|bucket| bucket["key"].as_str().map(String::from)).collect())
        .unwrap_or_default()
}

// ---- Entities ---------------------------------------------------------------

/// What an entity id names. The wire id is `kind:value`.
#[derive(Clone, Debug, PartialEq)]
enum Entity {
    Ip(String),
    Cidr(String),
    Asn(i64),
    Session(String),
    Payload(String),
    /// `attackers-v1` document id, with the addresses it holds once resolved.
    Identity { id: String, ips: Vec<String> },
    /// `campaigns-v1` document id, which is the campaign's /24 (or v6) CIDR.
    Campaign(String),
    /// `kind:value` of an infrastructure cluster; served as the indicator.
    Cluster { kind: String, value: String },
    Ioc { kind: String, value: String },
}

impl Entity {
    fn kind(&self) -> &'static str {
        match self {
            Entity::Ip(_) => "ip",
            Entity::Cidr(_) => "cidr",
            Entity::Asn(_) => "asn",
            Entity::Session(_) => "session",
            Entity::Payload(_) => "payload",
            Entity::Identity { .. } => "identity",
            Entity::Campaign(_) => "campaign",
            Entity::Cluster { .. } => "cluster",
            Entity::Ioc { .. } => "ioc",
        }
    }

    fn value(&self) -> String {
        match self {
            Entity::Ip(v) | Entity::Cidr(v) | Entity::Session(v) | Entity::Payload(v) | Entity::Campaign(v) => v.clone(),
            Entity::Asn(n) => n.to_string(),
            Entity::Identity { id, .. } => id.clone(),
            Entity::Cluster { kind, value } | Entity::Ioc { kind, value } => format!("{kind}:{value}"),
        }
    }

    fn id(&self) -> String {
        format!("{}:{}", self.kind(), self.value())
    }

    fn indicator(&self) -> Option<(&str, &str)> {
        match self {
            Entity::Cluster { kind, value } | Entity::Ioc { kind, value } => Some((kind, value)),
            _ => None,
        }
    }
}

/// `1.2.3.0/24` with a sane minimum prefix so one id cannot scan the world.
fn valid_cidr(text: &str) -> Option<String> {
    let (address, prefix) = text.split_once('/')?;
    let ip: IpAddr = address.trim().parse().ok()?;
    let prefix: u8 = prefix.trim().parse().ok()?;
    let (min, max) = if ip.is_ipv4() { (8, 32) } else { (32, 128) };
    (min..=max).contains(&prefix).then(|| format!("{ip}/{prefix}"))
}

fn is_hex_hash(text: &str) -> bool {
    matches!(text.len(), 32 | 40 | 64) && text.chars().all(|c| c.is_ascii_hexdigit())
}

fn bad_entity(message: &str) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, message.to_string())
}

fn indicator_pair(text: &str) -> Result<(String, String), (StatusCode, String)> {
    let (kind, value) = text.split_once(':').ok_or_else(|| bad_entity("expected kind:value after ioc:/cluster:"))?;
    let kind = kind.trim();
    if ioc_kind(kind).is_none() || value.trim().is_empty() || value.len() > 2048 {
        return Err(bad_entity("unknown indicator kind or empty value"));
    }
    Ok((kind.to_string(), value.trim().to_string()))
}

/// Parses an entity id. `kind:value` with kind one of ip (source), cidr
/// (network, net), asn, session, payload (hash, sha256), identity, campaign,
/// cluster or ioc. A bare id is inferred: an address, a CIDR, `AS<n>`, a
/// 32/40/64-digit hex hash, otherwise a session id.
fn parse_entity(raw: &str) -> Result<Entity, (StatusCode, String)> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 2048 {
        return Err(bad_entity("invalid id"));
    }
    if let Some((prefix, rest)) = raw.split_once(':') {
        let rest = rest.trim();
        let known = matches!(
            prefix,
            "ip" | "source" | "cidr" | "network" | "net" | "asn" | "session" | "payload" | "hash" | "sha256" | "identity" | "campaign" | "cluster" | "ioc"
        );
        if known {
            if rest.is_empty() {
                return Err(bad_entity("empty entity value"));
            }
            return match prefix {
                "ip" | "source" => rest.parse::<IpAddr>().map(|ip| Entity::Ip(ip.to_string())).map_err(|_| bad_entity("invalid ip")),
                "cidr" | "network" | "net" => valid_cidr(rest).map(Entity::Cidr).ok_or_else(|| bad_entity("invalid cidr")),
                "asn" => asn_number(rest).map(Entity::Asn),
                "session" => Ok(Entity::Session(rest.to_string())),
                "payload" | "hash" | "sha256" => Ok(Entity::Payload(rest.to_ascii_lowercase())),
                "identity" => Ok(Entity::Identity { id: rest.to_string(), ips: vec![] }),
                "campaign" => valid_cidr(rest).map(Entity::Campaign).ok_or_else(|| bad_entity("campaign ids are CIDRs")),
                "cluster" => indicator_pair(rest).map(|(kind, value)| Entity::Cluster { kind, value }),
                _ => indicator_pair(rest).map(|(kind, value)| Entity::Ioc { kind, value }),
            };
        }
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(Entity::Ip(ip.to_string()));
    }
    if let Some(cidr) = valid_cidr(raw) {
        return Ok(Entity::Cidr(cidr));
    }
    let upper = raw.to_ascii_uppercase();
    if let Some(digits) = upper.strip_prefix("AS").filter(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit())) {
        return asn_number(digits).map(Entity::Asn);
    }
    if is_hex_hash(raw) {
        return Ok(Entity::Payload(raw.to_ascii_lowercase()));
    }
    if raw.contains(':') {
        return Err(bad_entity("unknown entity kind; use ip:, cidr:, asn:, session:, payload:, identity:, campaign:, cluster: or ioc:"));
    }
    Ok(Entity::Session(raw.to_string()))
}

/// `source.ip` matches the address, or the sensor's own `honeypot.src_ip` when
/// the row has no `source.ip`.
fn ip_match(ip: &str) -> Value {
    json!({"bool": {"should": [
        {"term": {"source.ip": ip}},
        {"bool": {
            "filter": [{"bool": {"should": FALLBACK_ADDRESS_FIELDS.iter().map(|field| json!({"term": {*field: ip}})).collect::<Vec<_>>(), "minimum_should_match": 1}}],
            "must_not": [{"exists": {"field": "source.ip"}}]
        }}
    ], "minimum_should_match": 1}})
}

/// The event-index clause for an entity.
fn entity_clause(entity: &Entity) -> Value {
    match entity {
        Entity::Ip(ip) => ip_match(ip),
        Entity::Cidr(cidr) | Entity::Campaign(cidr) => json!({"term": {"source.ip": cidr}}),
        Entity::Asn(asn) => json!({"term": {"source.as.asn": asn}}),
        Entity::Session(id) => any_of(SESSION_FIELDS, id),
        Entity::Payload(hash) => json!({"term": {"honeypot.canonical_shasum": hash}}),
        Entity::Identity { ips, .. } if ips.is_empty() => json!({"match_none": {}}),
        Entity::Identity { ips, .. } => json!({"terms": {"source.ip": ips}}),
        Entity::Cluster { kind, value } | Entity::Ioc { kind, value } => {
            ioc_kind(kind).and_then(|def| ioc_value_clause(def, value).ok()).unwrap_or_else(|| json!({"match_none": {}}))
        }
    }
}

fn entity_extra_must_not(entity: &Entity) -> Vec<Value> {
    entity.indicator().and_then(|(kind, _)| ioc_kind(kind)).map(ioc_extra_must_not).unwrap_or_default()
}

fn entity_scope(entity: &Entity, range: &str) -> Value {
    ioc_scope(vec![time_range(range), entity_clause(entity)], entity_extra_must_not(entity))
}

/// The clause that matches the entity's addresses on a store whose address
/// field is `field` (`src_ip` on ml-anomalies and llm-analysis).
fn entity_ip_clause(entity: &Entity, field: &str) -> Option<Value> {
    match entity {
        Entity::Ip(ip) => Some(json!({"term": {field: ip}})),
        Entity::Cidr(cidr) | Entity::Campaign(cidr) => Some(json!({"term": {field: cidr}})),
        Entity::Identity { ips, .. } if !ips.is_empty() => Some(json!({"terms": {field: ips}})),
        _ => None,
    }
}

const IDENTITY_IP_CAP: usize = 500;

/// Resolves what the id alone cannot: an identity's addresses, a campaign's
/// existence. 404 when the document is missing; fleet addresses are 404 too.
async fn resolve_entity(state: &AppState, entity: Entity) -> Result<Entity, (StatusCode, String)> {
    let missing = || (StatusCode::NOT_FOUND, "no such entity".to_string());
    match entity {
        Entity::Ip(ref ip) if crate::events::is_fleet_address(ip) => Err(missing()),
        Entity::Cidr(ref cidr) if cidr.split('/').next().is_some_and(crate::events::is_fleet_address) => Err(missing()),
        Entity::Identity { id, .. } => {
            let id = validate_id(id)?;
            let doc = state.es.get_doc("attackers-v1", &id).await.map_err(bad_gateway)?.ok_or_else(missing)?;
            let ips = identity_ips(&doc);
            Ok(Entity::Identity { id, ips })
        }
        Entity::Campaign(cidr) => {
            state.es.get_doc("campaigns-v1", &cidr).await.map_err(bad_gateway)?.ok_or_else(missing)?;
            Ok(Entity::Campaign(cidr))
        }
        other => Ok(other),
    }
}

/// An identity's non-fleet addresses (`ips`), bounded.
fn identity_ips(doc: &Value) -> Vec<String> {
    doc["ips"]
        .as_array()
        .map(|ips| {
            ips.iter()
                .filter_map(Value::as_str)
                .filter(|ip| ip.parse::<IpAddr>().is_ok() && !crate::events::is_fleet_address(ip))
                .take(IDENTITY_IP_CAP)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

// ---- Timeline ---------------------------------------------------------------

const TIMELINE_DEFAULT_LIMIT: u64 = 100;
const TIMELINE_MAX_LIMIT: u64 = 500;

fn timeline_events_body(entity: &Entity, range: &str, limit: u64) -> Value {
    json!({"size": limit, "track_total_hits": true, "sort": [{"@timestamp": {"order": "desc"}}], "query": entity_scope(entity, range)})
}

fn severity_word(value: &str) -> Option<&'static str> {
    match value {
        "critical" => Some("critical"),
        "high" => Some("high"),
        "medium" => Some("medium"),
        "low" => Some("low"),
        "info" => Some("info"),
        _ => None,
    }
}

fn short(hash: &str) -> String {
    hash.chars().take(16).collect()
}

/// Timeline item. `href` is the dashboard route of the record behind it.
fn timeline_item(id: &str, at: &str, kind: &str, title: String, detail: String, severity: Option<&str>, href: String) -> Value {
    json!({"id": id, "at": at, "kind": kind, "title": title, "detail": detail, "severity": severity, "href": href})
}

/// One event hit as a timeline item: `alert` for Suricata alerts, `canary`
/// for canarytoken triggers, `capture` for a payload download, else `event`.
fn event_item(hit: &Value) -> Option<Value> {
    let id = hit["_id"].as_str()?;
    let src = &hit["_source"];
    let at = src["@timestamp"].as_str()?;
    let row = crate::events::row_from_source(src);
    let pivots = &row.pivots;
    let source = if row.src_ip.is_empty() { "-" } else { row.src_ip.as_str() };
    let detail = format!("{source} · {}", row.sensor);
    let severity = row.severity;
    let item = if row.sensor == "canarytokens" {
        timeline_item(id, at, "canary", format!("Canarytoken fired: {}", row.detail), detail, Some("critical"), format!("/events/{id}"))
    } else if row.kind == Some("alert") || !pivots.alert.is_empty() {
        let title = if pivots.alert.is_empty() { row.detail.clone() } else { pivots.alert.clone() };
        timeline_item(id, at, "alert", title, detail, severity, format!("/events/{id}"))
    } else if row.kind == Some("download") && !pivots.shasum.is_empty() {
        timeline_item(id, at, "capture", format!("Payload captured: {}…", short(&pivots.shasum)), detail, severity, format!("/payloads/{}", pivots.shasum))
    } else {
        let title = if row.detail.is_empty() { row.kind.unwrap_or("event").to_string() } else { row.detail.clone() };
        let service = [row.proto.to_uppercase(), row.port.clone()].into_iter().filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" ");
        let detail = if service.is_empty() { detail } else { format!("{detail} · {service}") };
        timeline_item(id, at, "event", title, detail, severity, format!("/events/{id}"))
    };
    Some(item)
}

/// The session ids of event hits, in every field a sensor can write one.
fn hit_sessions(hits: &[Value]) -> Vec<String> {
    let mut sessions: Vec<String> = hits
        .iter()
        .flat_map(|hit| {
            let src = &hit["_source"];
            [&src["honeypot"]["session"], &src["honeypot"]["session_id"], &src["session"]["id"]]
                .into_iter()
                .filter_map(|v| v.as_str().filter(|s| !s.is_empty()).map(String::from))
                .collect::<Vec<_>>()
        })
        .collect();
    sessions.sort();
    sessions.dedup();
    sessions.truncate(200);
    sessions
}

fn hit_ids(hits: &[Value]) -> Vec<String> {
    hits.iter().filter_map(|hit| hit["_id"].as_str().map(String::from)).collect()
}

/// ML anomalies that name the entity's address or one of its events.
fn timeline_ml_body(entity: &Entity, range: &str, limit: u64, event_ids: &[String]) -> Option<Value> {
    let mut should = Vec::new();
    should.extend(entity_ip_clause(entity, "src_ip"));
    if !event_ids.is_empty() {
        should.push(json!({"terms": {"source_event_id": event_ids}}));
    }
    if should.is_empty() {
        return None;
    }
    Some(json!({
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [time_range(range), {"bool": {"should": should, "minimum_should_match": 1}}], "must_not": [fleet_store_exclusion()]}}
    }))
}

/// LLM analyses of the entity's addresses, sessions or payload.
fn timeline_llm_body(entity: &Entity, range: &str, limit: u64, sessions: &[String]) -> Option<Value> {
    let mut should = Vec::new();
    should.extend(entity_ip_clause(entity, "src_ip"));
    if !sessions.is_empty() {
        should.push(json!({"terms": {"session_id": sessions}}));
    }
    if let Entity::Payload(hash) = entity {
        should.push(json!({"term": {"payload_sha256": hash}}));
    }
    if should.is_empty() {
        return None;
    }
    Some(json!({
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [time_range(range), {"bool": {"should": should, "minimum_should_match": 1}}], "must_not": [fleet_store_exclusion()]}}
    }))
}

fn ml_item(hit: &Value) -> Option<Value> {
    let id = hit["_id"].as_str()?;
    let src = &hit["_source"];
    let at = src["@timestamp"].as_str()?;
    let title = src["explanation"].as_str().filter(|text| !text.is_empty()).unwrap_or("Statistical outlier").to_string();
    let score = src["composite_score"].as_f64().map(|score| format!("ML score {score:.2}")).unwrap_or_else(|| "ML score -".into());
    let detail = format!("{score} · {}", src["status"].as_str().unwrap_or("open"));
    Some(timeline_item(id, at, "anomaly", title, detail, src["severity"].as_str().and_then(severity_word), format!("/ml-anomalies/{id}")))
}

fn llm_item(hit: &Value) -> Option<Value> {
    let id = hit["_id"].as_str()?;
    let src = &hit["_source"];
    let at = src["@timestamp"].as_str()?;
    let title = src["summary"].as_str().filter(|text| !text.is_empty()).unwrap_or("(no summary)").to_string();
    let detail = format!("AI-generated · {}", src["intent"].as_str().unwrap_or("unknown"));
    Some(timeline_item(id, at, "llm", title, detail, src["severity"].as_str().and_then(severity_word), format!("/llm-analysis/{id}")))
}

fn hits_of(result: &Value) -> Vec<Value> {
    result["hits"]["hits"].as_array().cloned().unwrap_or_default()
}

fn parsed_time(item: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    item["at"].as_str().and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok()).map(|at| at.with_timezone(&chrono::Utc))
}

/// Newest first by instant (not by string, since stores write different
/// fractional-second widths), cut to `limit`. Returns the pre-cut total.
fn merge_timeline(mut items: Vec<Value>, limit: usize) -> (usize, Vec<Value>) {
    items.sort_by(|a, b| parsed_time(b).cmp(&parsed_time(a)).then_with(|| a["id"].as_str().cmp(&b["id"].as_str())));
    let total = items.len();
    items.truncate(limit);
    (total, items)
}

fn entity_json(entity: &Entity) -> Value {
    json!({"kind": entity.kind(), "value": entity.value()})
}

#[utoipa::path(get, path = "/api/v1/entities/{id}/timeline", summary = "Chronological activity for one entity: events, alerts, canary triggers, ML anomalies and LLM analyses.",
    params(
        ("id" = inline(String), Path, description = "Entity id `kind:value`: ip:1.2.3.4 (alias source:), cidr:1.2.3.0/24 (network:; encode the slash), asn:13335, session:<id>, payload:<sha256> (hash:), identity:<attackers-v1 id>, campaign:<cidr>, cluster:<kind>:<value>, ioc:<kind>:<value>. A bare id is inferred: address, CIDR, AS<n>, 32/40/64-digit hex hash, else session."),
        ("range" = inline(Option<String>), Query, description = "1h, 6h, 24h (default), 7d or 30d."),
        ("limit" = inline(Option<u64>), Query, description = "Items to return, 1-500 (default 100).")
    ),
    responses(
        (status = 200, description = "{id, entity: {kind, value}, range, total, items: [{id, at, kind, title, detail, severity, href}]}, newest first. kind is event, alert, capture, canary, anomaly or llm; severity is critical/high/medium/low/info or null; href is the dashboard route of the record. total is the number of items found before the limit. Nothing in range is an empty `items` list. ML anomalies match the entity's address or the ids of its returned events; LLM analyses its address, sessions or payload hash. Fleet addresses are excluded.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Malformed id, bad range or bad limit.", body = String),
        (status = 404, description = "Identity or campaign does not exist, or the id is a fleet address.", body = String),
        (status = 502, description = "Elasticsearch failed.", body = String)
    ), security(("serviceToken" = [])))]
pub async fn entity_timeline(State(state): State<AppState>, Path(id): Path<String>, Query(query): Query<TimelineQuery>) -> Response {
    let range = range_or(&query.range, "24h")?;
    let limit = query.limit.unwrap_or(TIMELINE_DEFAULT_LIMIT);
    if limit == 0 || limit > TIMELINE_MAX_LIMIT {
        return Err((StatusCode::BAD_REQUEST, format!("limit must be 1-{TIMELINE_MAX_LIMIT}")));
    }
    let entity = resolve_entity(&state, parse_entity(&id)?).await?;
    let events = state.es.search(timeline_events_body(&entity, &range, limit)).await.map_err(bad_gateway)?;
    let hits = hits_of(&events);
    let (ids, sessions) = (hit_ids(&hits), {
        let mut sessions = hit_sessions(&hits);
        if let Entity::Session(own) = &entity {
            sessions.push(own.clone());
        }
        sessions
    });
    let ml_body = timeline_ml_body(&entity, &range, limit, &ids);
    let llm_body = timeline_llm_body(&entity, &range, limit, &sessions);
    let (ml, llm) = futures::try_join!(
        async { match ml_body { Some(body) => state.es.search_index(&["ml-anomalies"], body).await, None => Ok(Value::Null) } },
        async { match llm_body { Some(body) => state.es.search_index(&["llm-analysis"], body).await, None => Ok(Value::Null) } },
    )
    .map_err(bad_gateway)?;
    Ok((StatusCode::OK, Json(timeline_response(&entity, &range, limit as usize, &events, &ml, &llm))))
}

/// The timeline document from the three store responses (`Null` for a store
/// that was not queried).
fn timeline_response(entity: &Entity, range: &str, limit: usize, events: &Value, ml: &Value, llm: &Value) -> Value {
    let mut items: Vec<Value> = hits_of(events).iter().filter_map(event_item).collect();
    items.extend(hits_of(ml).iter().filter_map(ml_item));
    items.extend(hits_of(llm).iter().filter_map(llm_item));
    let (found, items) = merge_timeline(items, limit);
    json!({"id": entity.id(), "entity": entity_json(entity), "range": range.trim_start_matches("now-"), "total": found, "items": items})
}

// ---- Related ----------------------------------------------------------------

/// Fingerprint kinds that every client of a protocol presents, so sharing one
/// says nothing (an RFB banner, a generic User-Agent).
const NOISY_FINGERPRINT_KINDS: &[&str] = &["client banner", "User-Agent"];
const RELATED_ITEMS: u64 = 10;
const RELATED_PIVOTS: usize = 5;
const RELATED_IP_CAP: usize = 100;

fn terms_agg(field: &str, size: u64) -> Value {
    json!({"terms": {"field": field, "size": size}})
}

/// Stage 1: what the entity's own events carry.
fn related_scope_body(entity: &Entity, range: &str) -> Value {
    let names = crate::secrets_boundary::CREDENTIAL_SENSORS;
    let mut body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": entity_scope(entity, range),
        "aggs": {
            "sessions": {
                "terms": {"field": "honeypot.session", "size": RELATED_ITEMS, "order": {"last": "desc"}},
                "aggs": {"last": {"max": {"field": "@timestamp"}}}
            },
            "payloads": terms_agg("honeypot.canonical_shasum", RELATED_ITEMS),
            "fingerprints": {
                "filter": {"bool": {"must_not": [{"terms": {"honeypot.canonical_fingerprint_kind": BANNER_KINDS}}]}},
                "aggs": {"v": {"terms": {"field": "honeypot.canonical_fingerprint", "size": RELATED_ITEMS}, "aggs": {"kind": terms_agg("honeypot.canonical_fingerprint_kind", 1)}}}
            },
            "credentials": {
                "filter": {"bool": {
                    "filter": [{"bool": {"should": [{"exists": {"field": USER_FIELD}}, {"exists": {"field": PASS_FIELD}}], "minimum_should_match": 1}}],
                    "must_not": [{"terms": {"event.sensor": names}}]
                }},
                "aggs": {"v": {"multi_terms": {"terms": [{"field": USER_FIELD, "missing": ""}, {"field": PASS_FIELD, "missing": ""}], "size": RELATED_ITEMS}}}
            },
            "asns": {"terms": {"field": "source.as.asn", "size": RELATED_ITEMS}, "aggs": {"org": terms_agg("source.as.organization_name", 1)}},
            "sensors": terms_agg("event.sensor", RELATED_ITEMS),
            "commands": terms_agg("honeypot.canonical_command", RELATED_ITEMS),
            "urls": terms_agg("honeypot.url", RELATED_ITEMS),
            "signatures": terms_agg("suricata.eve.alert.signature.keyword", RELATED_ITEMS),
            "cves": {"terms": {"field": "honeypot.cve", "size": RELATED_ITEMS}},
            "suricata_cves": terms_agg("suricata.eve.alert.metadata.cve.keyword", RELATED_ITEMS)
        }
    });
    let aggs = body["aggs"].as_object_mut().expect("aggs object");
    for (name, agg) in source_terms_aggs("sources", RELATED_ITEMS).into_iter().chain(source_terms_aggs("addresses", 200)) {
        aggs.insert(name, agg);
    }
    body
}

fn bucket_list(result: &Value, path: &[&str]) -> Vec<(String, u64, Value)> {
    let mut node = &result["aggregations"];
    for step in path {
        node = &node[*step];
    }
    node["buckets"]
        .as_array()
        .map(|buckets| {
            buckets
                .iter()
                .filter_map(|bucket| {
                    let key = match &bucket["key"] {
                        Value::String(text) => text.clone(),
                        Value::Array(parts) => parts.iter().map(|p| p.as_str().map(String::from).unwrap_or_else(|| p.to_string())).collect::<Vec<_>>().join(":"),
                        Value::Null => return None,
                        other => other.to_string(),
                    };
                    (!key.is_empty() && key != ":").then(|| (key, bucket["doc_count"].as_u64().unwrap_or(0), bucket.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn related_item(id: &str, label: Option<String>, note: Option<String>, count: u64, reason: String) -> Value {
    json!({"id": id, "label": label, "note": note, "count": count, "reason": reason})
}

fn related_group(kind: &str, label: &str, items: Vec<Value>) -> Value {
    json!({"kind": kind, "label": label, "items": items})
}

/// `a.b.c.0/24` for an IPv4 address, `/64` for IPv6.
fn subnet_of(ip: &str) -> Option<String> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            Some(format!("{a}.{b}.{c}.0/24"))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            Some(format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3]))
        }
    }
}

/// Source addresses of the scope grouped by their subnet, busiest first.
fn subnet_counts(addresses: &[(String, u64)]) -> Vec<(String, u64, usize)> {
    let mut by_subnet: std::collections::HashMap<String, (u64, usize)> = std::collections::HashMap::new();
    for (ip, count) in addresses {
        if let Some(subnet) = subnet_of(ip) {
            let entry = by_subnet.entry(subnet).or_default();
            entry.0 += count;
            entry.1 += 1;
        }
    }
    let mut rows: Vec<(String, u64, usize)> = by_subnet.into_iter().map(|(subnet, (events, ips))| (subnet, events, ips)).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows
}

/// Stage 2: other sources that share a pivot with the entity, found among the
/// events outside it. `pivots` come from stage 1.
struct SharedPivots {
    payloads: Vec<String>,
    fingerprints: Vec<String>,
    credentials: Vec<(String, String)>,
    subnet: Option<String>,
    asn: Option<i64>,
}

fn shared_pivots(entity: &Entity, scope: &Value) -> SharedPivots {
    let payloads = match entity {
        Entity::Payload(_) => vec![],
        _ => bucket_list(scope, &["payloads"]).into_iter().map(|(key, _, _)| key).take(RELATED_PIVOTS).collect(),
    };
    let fingerprints = bucket_list(scope, &["fingerprints", "v"])
        .into_iter()
        .filter(|(_, _, bucket)| {
            let kind = bucket["kind"]["buckets"][0]["key"].as_str().unwrap_or("");
            !NOISY_FINGERPRINT_KINDS.contains(&kind)
        })
        .map(|(key, _, _)| key)
        .take(RELATED_PIVOTS)
        .collect();
    let credentials = bucket_list(scope, &["credentials", "v"])
        .into_iter()
        .filter_map(|(key, _, _)| key.split_once(':').map(|(user, pass)| (user.to_string(), pass.to_string())))
        .filter(|(user, pass)| !(user.is_empty() && pass.is_empty()))
        .take(RELATED_PIVOTS)
        .collect();
    let (subnet, asn) = match entity {
        Entity::Ip(ip) => (
            subnet_of(ip),
            bucket_list(scope, &["asns"]).first().and_then(|(key, _, _)| key.parse::<i64>().ok()),
        ),
        _ => (None, None),
    };
    SharedPivots { payloads, fingerprints, credentials, subnet, asn }
}

fn credential_clause(user: &str, pass: &str) -> Value {
    ioc_value_clause(ioc_kind("credential").expect("credential kind"), &format!("{user}:{pass}")).unwrap_or_else(|_| json!({"match_none": {}}))
}

fn sources_under(filter: Value) -> Value {
    let aggs: serde_json::Map<String, Value> = source_terms_aggs("v", RELATED_ITEMS).into_iter().collect();
    json!({"filter": filter, "aggs": aggs})
}

/// The stage 2 body, or `None` when the entity has nothing to pivot on.
fn related_shared_body(entity: &Entity, range: &str, pivots: &SharedPivots) -> Option<Value> {
    let mut aggs = serde_json::Map::new();
    if !pivots.payloads.is_empty() {
        aggs.insert("payload".into(), sources_under(json!({"terms": {"honeypot.canonical_shasum": pivots.payloads}})));
    }
    if !pivots.fingerprints.is_empty() {
        aggs.insert("fingerprint".into(), sources_under(json!({"terms": {"honeypot.canonical_fingerprint": pivots.fingerprints}})));
    }
    if !pivots.credentials.is_empty() {
        let should: Vec<Value> = pivots.credentials.iter().map(|(user, pass)| credential_clause(user, pass)).collect();
        aggs.insert("credential".into(), sources_under(json!({"bool": {
            "filter": [{"bool": {"should": should, "minimum_should_match": 1}}],
            "must_not": secret_exclusion()
        }})));
    }
    if let Some(subnet) = &pivots.subnet {
        aggs.insert("subnet".into(), sources_under(json!({"term": {"source.ip": subnet}})));
    }
    if let Some(asn) = pivots.asn {
        aggs.insert("asn".into(), sources_under(json!({"term": {"source.as.asn": asn}})));
    }
    if aggs.is_empty() {
        return None;
    }
    Some(json!({
        "size": 0,
        "track_total_hits": false,
        "query": ioc_scope(vec![time_range(range)], {
            let mut excluded = entity_extra_must_not(entity);
            excluded.push(entity_clause(entity));
            excluded
        }),
        "aggs": aggs
    }))
}

fn related_flows_body(ips: &[String], range: &str) -> Value {
    json!({
        "size": RELATED_ITEMS,
        "sort": [{"last": {"order": "desc", "unmapped_type": "date"}}],
        "_source": ["community_id", "src_ip", "dst_ip", "dst_port", "events", "sensors", "families", "last"],
        "query": {"bool": {"filter": [{"terms": {"src_ip.keyword": ips}}, {"range": {"last": {"gte": range}}}]}}
    })
}

fn related_identities_body(ips: &[String], exclude: Option<&str>) -> Value {
    let must_not: Vec<Value> = exclude.map(|id| json!({"ids": {"values": [id]}})).into_iter().collect();
    json!({
        "size": RELATED_ITEMS,
        "sort": [{"events": {"order": "desc", "unmapped_type": "long"}}],
        "_source": ["id", "ips", "events", "first", "last", "sensors"],
        "query": {"bool": {"filter": [{"terms": {"ips.keyword": ips}}], "must_not": must_not}}
    })
}

fn related_campaigns_body(subnets: &[String], exclude: Option<&str>) -> Value {
    let must_not: Vec<Value> = exclude.map(|id| json!({"ids": {"values": [id]}})).into_iter().collect();
    json!({
        "size": RELATED_ITEMS,
        "sort": [{"score": {"order": "desc", "unmapped_type": "long"}}],
        "_source": ["cidr", "score", "events", "unique_ips", "last"],
        "query": {"bool": {"filter": [{"ids": {"values": subnets}}], "must_not": must_not}}
    })
}

/// The addresses to look up in the address-keyed stores: the entity's own for
/// an address, else the busiest sources of its scope.
fn related_addresses(entity: &Entity, scope: &Value) -> Vec<String> {
    match entity {
        Entity::Ip(ip) => vec![ip.clone()],
        Entity::Identity { ips, .. } => ips.iter().take(RELATED_IP_CAP).cloned().collect(),
        _ => merged_sources(&scope["aggregations"], "addresses", RELATED_IP_CAP).into_iter().map(|(ip, _)| ip).collect(),
    }
}

fn count_items(buckets: Vec<(String, u64, Value)>, skip: Option<&str>, reason: &str) -> Vec<Value> {
    buckets
        .into_iter()
        .filter(|(key, _, _)| Some(key.as_str()) != skip)
        .map(|(key, count, _)| related_item(&key, None, Some(format!("{count} events")), count, reason.to_string()))
        .collect()
}

/// Stage 1 groups: what the entity's events carry. The entity itself is
/// never listed as related to itself.
fn scope_groups(entity: &Entity, scope: &Value) -> Vec<Value> {
    let id = entity.id();
    let own = |kind: &str| -> Option<String> {
        match (entity, kind) {
            (Entity::Ip(ip), "source") => Some(ip.clone()),
            (Entity::Session(session), "session") => Some(session.clone()),
            (Entity::Payload(hash), "payload") => Some(hash.clone()),
            (Entity::Asn(asn), "asn") => Some(asn.to_string()),
            _ => None,
        }
    };
    let (own_source, own_session, own_payload, own_asn) = (own("source"), own("session"), own("payload"), own("asn"));
    let sessions: Vec<Value> = bucket_list(scope, &["sessions"])
        .into_iter()
        .filter(|(key, _, _)| Some(key) != own_session.as_ref())
        .map(|(key, count, bucket)| {
            related_item(&key, None, Some(format!("{count} events")), count, format!("session with events inside {id}")).tap_last(bucket["last"]["value_as_string"].as_str())
        })
        .collect();
    let asns: Vec<Value> = bucket_list(scope, &["asns"])
        .into_iter()
        .filter(|(key, _, _)| Some(key) != own_asn.as_ref())
        .map(|(key, count, bucket)| {
            let org = bucket["org"]["buckets"][0]["key"].as_str().map(String::from);
            related_item(&key, org, Some(format!("{count} events")), count, format!("AS of sources inside {id}"))
        })
        .collect();
    let networks: Vec<Value> = subnet_counts(&merged_sources(&scope["aggregations"], "addresses", 200))
        .into_iter()
        .filter(|(subnet, _, _)| !matches!(entity, Entity::Cidr(c) | Entity::Campaign(c) if c == subnet))
        .take(RELATED_ITEMS as usize)
        .map(|(subnet, events, ips)| related_item(&subnet, None, Some(format!("{ips} {}", if ips == 1 { "address" } else { "addresses" })), events, format!("/24 (/64) of sources inside {id}")))
        .collect();
    let fingerprints: Vec<Value> = bucket_list(scope, &["fingerprints", "v"])
        .into_iter()
        .map(|(key, count, bucket)| {
            let kind = bucket["kind"]["buckets"][0]["key"].as_str().map(String::from);
            related_item(&key, None, kind, count, format!("fingerprint presented inside {id}"))
        })
        .collect();
    let indicator = |agg: &str, reason: &str| count_items(bucket_list(scope, &[agg]), None, reason);
    let mut cves = indicator("cves", &format!("CVE referenced inside {id}"));
    for item in indicator("suricata_cves", &format!("CVE referenced inside {id}")) {
        cves.push(json!({"id": normalize_cve(item["id"].as_str().unwrap_or("")), "label": item["label"], "note": item["note"], "count": item["count"], "reason": item["reason"]}));
    }
    vec![
        related_group("source", "Source IPs", count_items(merged_sources(&scope["aggregations"], "sources", RELATED_ITEMS as usize).into_iter().map(|(ip, count)| (ip, count, Value::Null)).collect(), own_source.as_deref(), &format!("source active inside {id}"))),
        related_group("session", "Sessions", sessions),
        related_group("payload", "Payloads", count_items(bucket_list(scope, &["payloads"]), own_payload.as_deref(), &format!("payload delivered inside {id}"))),
        related_group("credential", "Credentials", count_items(bucket_list(scope, &["credentials", "v"]), None, &format!("credential tried inside {id}"))),
        related_group("fingerprint", "Fingerprints", fingerprints),
        related_group("command", "Commands", indicator("commands", &format!("command run inside {id}"))),
        related_group("url", "URLs", indicator("urls", &format!("URL seen inside {id}"))),
        related_group("signature", "IDS signatures", indicator("signatures", &format!("signature fired inside {id}"))),
        related_group("cve", "CVEs", cves),
        related_group("asn", "Autonomous systems", asns),
        related_group("network", "Networks", networks),
        related_group("sensor", "Sensors", count_items(bucket_list(scope, &["sensors"]), None, &format!("sensor that recorded {id}"))),
    ]
}

trait TapLast {
    fn tap_last(self, last: Option<&str>) -> Value;
}

impl TapLast for Value {
    /// Folds the session's last-seen time into its note.
    fn tap_last(mut self, last: Option<&str>) -> Value {
        if let (Some(last), Some(note)) = (last, self["note"].as_str().map(String::from)) {
            self["note"] = json!(format!("{note} · last {last}"));
        }
        self
    }
}

/// Stage 2 groups: other sources sharing a pivot with the entity.
fn shared_groups(entity: &Entity, shared: &Value) -> Vec<Value> {
    let id = entity.id();
    [
        ("payload", "Sources delivering the same payload", format!("delivered a payload also seen inside {id}")),
        ("fingerprint", "Sources with the same fingerprint", format!("presented a fingerprint also seen inside {id}")),
        ("credential", "Sources trying the same credentials", format!("tried a credential also tried inside {id}")),
        ("subnet", "Sources in the same /24", format!("shares the /24 (/64) of {id}")),
        ("asn", "Sources in the same AS", format!("shares the AS of {id}")),
    ]
    .into_iter()
    .map(|(agg, label, reason)| {
        let found = merged_sources(&shared["aggregations"][agg], "v", RELATED_ITEMS as usize).into_iter().map(|(ip, count)| (ip, count, Value::Null)).collect();
        related_group("source", label, count_items(found, None, &reason))
    })
    .collect()
}

fn identity_items(result: &Value, ips: &[String], id: &str) -> Vec<Value> {
    hits_of(result)
        .iter()
        .filter_map(|hit| {
            let src = &hit["_source"];
            let identity = src["id"].as_str().or_else(|| hit["_id"].as_str())?;
            let identity_ips: Vec<&str> = src["ips"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            let shared = identity_ips.iter().filter(|ip| ips.iter().any(|mine| mine == **ip)).count() as u64;
            Some(related_item(identity, Some(identity.chars().take(8).collect()), Some(format!("{} IPs", identity_ips.len())), shared, format!("same attacker identity (attackers-v1) as addresses inside {id}")))
        })
        .collect()
}

fn flow_items(result: &Value, id: &str) -> Vec<Value> {
    hits_of(result)
        .iter()
        .filter_map(|hit| {
            let src = &hit["_source"];
            let community = src["community_id"].as_str()?;
            let events = src["events"].as_u64().unwrap_or(0);
            let sensors = src["sensors"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            let note = format!(
                "{} → {}:{} · {} events across {}",
                src["src_ip"].as_str().unwrap_or("?"),
                src["dst_ip"].as_str().unwrap_or("?"),
                src["dst_port"].as_u64().map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                events,
                sensors
            );
            Some(related_item(community, None, Some(note), events, format!("flow of an address inside {id} seen by several sensors (flow-links-v1)")))
        })
        .collect()
}

fn campaign_items(result: &Value, id: &str) -> Vec<Value> {
    hits_of(result)
        .iter()
        .filter_map(|hit| {
            let src = &hit["_source"];
            let cidr = src["cidr"].as_str().or_else(|| hit["_id"].as_str())?;
            let score = src["score"].as_u64().map(|s| format!("score {s}")).unwrap_or_default();
            Some(related_item(cidr, None, Some(score), src["events"].as_u64().unwrap_or(0), format!("campaign over a network inside {id} (campaigns-v1)")))
        })
        .collect()
}

#[utoipa::path(get, path = "/api/v1/entities/{id}/related", summary = "Entities that share pivots with one entity.",
    params(
        ("id" = inline(String), Path, description = "Entity id, same format as /entities/{id}/timeline."),
        ("range" = inline(Option<String>), Query, description = "1h, 6h, 24h, 7d (default) or 30d.")
    ),
    responses(
        (status = 200, description = "{id, entity: {kind, value}, range, groups: [{kind, label, items: [{id, label, note, count, reason}]}]}. Empty groups are dropped. Group kinds: source, session, payload, credential, fingerprint, command, url, signature, cve, asn, network (CIDR), sensor, identity (attackers-v1), flow (community id, flow-links-v1), campaign (campaigns-v1). Several `source` groups carry the sources that share a payload, fingerprint, credential, /24 or ASN with the entity (found outside it). `count` is events (flows: events; identities: shared addresses); `reason` states the relation. Credentials are `user:password` and never come from scrubbed sensors; fleet addresses are excluded.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Malformed id or bad range.", body = String),
        (status = 404, description = "Identity or campaign does not exist, or the id is a fleet address.", body = String),
        (status = 502, description = "Elasticsearch failed.", body = String)
    ), security(("serviceToken" = [])))]
pub async fn entity_related(State(state): State<AppState>, Path(id): Path<String>, Query(query): Query<RelatedQuery>) -> Response {
    let range = range_or(&query.range, "7d")?;
    let entity = resolve_entity(&state, parse_entity(&id)?).await?;
    let scope = state.es.search(related_scope_body(&entity, &range)).await.map_err(bad_gateway)?;
    let pivots = shared_pivots(&entity, &scope);
    let addresses = related_addresses(&entity, &scope);
    let subnets: Vec<String> = subnet_counts(&merged_sources(&scope["aggregations"], "addresses", 200)).into_iter().map(|(subnet, _, _)| subnet).take(50).collect();
    let own_identity = match &entity {
        Entity::Identity { id, .. } => Some(id.clone()),
        _ => None,
    };
    let own_campaign = match &entity {
        Entity::Campaign(cidr) => Some(cidr.clone()),
        _ => None,
    };
    let shared_body = related_shared_body(&entity, &range, &pivots);
    let (shared, identities, flows, campaigns) = futures::try_join!(
        async { match shared_body { Some(body) => state.es.search(body).await, None => Ok(Value::Null) } },
        async {
            if addresses.is_empty() { Ok(Value::Null) } else { state.es.search_index(&["attackers-v1"], related_identities_body(&addresses, own_identity.as_deref())).await }
        },
        async {
            if addresses.is_empty() { Ok(Value::Null) } else { state.es.search_index(&["flow-links-v1"], related_flows_body(&addresses, &range)).await }
        },
        async {
            if subnets.is_empty() { Ok(Value::Null) } else { state.es.search_index(&["campaigns-v1"], related_campaigns_body(&subnets, own_campaign.as_deref())).await }
        },
    )
    .map_err(bad_gateway)?;
    Ok((StatusCode::OK, Json(related_response(&entity, &range, &addresses, [&scope, &shared, &identities, &flows, &campaigns]))))
}

/// The related document from the stage 1 scope, the stage 2 shared-pivot
/// result and the identity, flow and campaign lookups, in that order.
fn related_response(entity: &Entity, range: &str, addresses: &[String], stores: [&Value; 5]) -> Value {
    let [scope, shared, identities, flows, campaigns] = stores;
    let entity_id = entity.id();
    let mut groups = scope_groups(entity, scope);
    groups.extend(shared_groups(entity, shared));
    groups.push(related_group("identity", "Attacker identities", identity_items(identities, addresses, &entity_id)));
    groups.push(related_group("flow", "Network flows", flow_items(flows, &entity_id)));
    groups.push(related_group("campaign", "Campaigns", campaign_items(campaigns, &entity_id)));
    groups.retain(|group| group["items"].as_array().is_some_and(|items| !items.is_empty()));
    json!({"id": entity_id, "entity": entity_json(entity), "range": range.trim_start_matches("now-"), "groups": groups})
}

#[utoipa::path(get, path = "/api/v1/investigate/asn/{id}", summary = "One ASN, aggregated from its events.", params(("id" = inline(String), Path, description = "AS number, with or without the AS prefix.")), responses((status = 200, description = "{asn, organization, provider, events, sources_total, first, last, sources: [{key, count}]} over EVENT_INDICES, top 50 sources.", body = inline(serde_json::Value), content_type = "application/json"), (status = 400, description = "Not an AS number.", body = String), (status = 404, description = "No events from this ASN.", body = inline(serde_json::Value), content_type = "application/json"), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn asn(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let asn = asn_number(&id)?;
    let result = state.es.search(asn_body(asn)).await.map_err(bad_gateway)?;
    if total(&result) == 0 {
        return Ok((StatusCode::NOT_FOUND, Json(Value::Null)));
    }
    Ok((StatusCode::OK, Json(json!({
        "asn": asn,
        "organization": top_key(&result, "organization"),
        "provider": top_key(&result, "provider"),
        "events": total(&result),
        "sources_total": result["aggregations"]["source_count"]["value"].clone(),
        "first": result["aggregations"]["first"]["value_as_string"].clone(),
        "last": result["aggregations"]["last"]["value_as_string"].clone(),
        "sources": key_counts(&result, "sources"),
    }))))
}

#[utoipa::path(get, path = "/api/v1/investigate/session/{id}/summary", summary = "One session summary, aggregated from its events.", params(("id" = inline(String), Path, description = "Session id.")), responses((status = 200, description = "{id, events, first, last, sensors, commands, sources} over EVENT_INDICES.", body = inline(serde_json::Value), content_type = "application/json"), (status = 404, description = "No such session.", body = inline(serde_json::Value), content_type = "application/json"), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn session_summary(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let id = validate_id(id)?;
    let result = state.es.search(session_summary_body(&id)).await.map_err(bad_gateway)?;
    if total(&result) == 0 {
        return Ok((StatusCode::NOT_FOUND, Json(Value::Null)));
    }
    Ok((StatusCode::OK, Json(json!({
        "id": id,
        "events": total(&result),
        "first": result["aggregations"]["first"]["value_as_string"].clone(),
        "last": result["aggregations"]["last"]["value_as_string"].clone(),
        "sensors": key_counts(&result, "sensors"),
        "commands": key_counts(&result, "commands"),
        "sources": key_counts(&result, "sources"),
    }))))
}

#[utoipa::path(get, path = "/api/v1/payloads/{id}/delivery", summary = "Events, sessions and sources that carried one payload hash.", params(("id" = inline(String), Path, description = "Payload SHA-256 (honeypot.canonical_shasum).")), responses((status = 200, description = "{total, events (newest 100), sessions: [{session, events, first, last}], sources: [{key, count}]}.", body = inline(serde_json::Value), content_type = "application/json"), (status = 404, description = "No event carries this payload hash.", body = inline(serde_json::Value), content_type = "application/json"), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn payload_delivery(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let hash = validate_id(id)?;
    let result = state.es.search(payload_delivery_body(&hash)).await.map_err(bad_gateway)?;
    if total(&result) == 0 {
        return Ok((StatusCode::NOT_FOUND, Json(Value::Null)));
    }
    let events = list_body(&result)["rows"].clone();
    let sessions = session_list(&result)["rows"].clone();
    Ok((StatusCode::OK, Json(json!({
        "total": total(&result),
        "events": events,
        "sessions": sessions,
        "sources": key_counts(&result, "sources"),
    }))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(value: &Value) -> String { value.to_string() }

    #[test]
    fn source_ranges_are_bounded() {
        assert_eq!(range(&RangeQuery { range: "24h".into() }).unwrap(), "now-24h");
        assert!(range(&RangeQuery { range: "forever".into() }).is_err());
    }

    #[test]
    fn source_addresses_must_parse() {
        assert!(source_ip("203.0.113.7".into()).is_ok());
        assert!(source_ip("2001:db8::1".into()).is_ok());
        assert_eq!(source_ip("not-an-ip".into()).unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn source_events_are_scoped_to_ip_and_range_and_capped() {
        let body = source_event_body("203.0.113.7", "now-24h");
        let query = rendered(&body["query"]);
        assert!(query.contains("\"source.ip\":\"203.0.113.7\""), "{query}");
        assert!(query.contains("\"gte\":\"now-24h\""), "{query}");
        assert!(query.contains("\"must_not\""), "the explorer's noise exclusion must apply: {query}");
        assert_eq!(body["size"], 100);
        assert_eq!(body["sort"][0]["@timestamp"]["order"], "desc");
    }

    #[test]
    fn source_timeline_reads_the_newest_window_oldest_first() {
        let body = json!({"total": 3, "rows": [{"n": 3}, {"n": 2}, {"n": 1}]});
        assert_eq!(oldest_first(body)["rows"], json!([{"n": 1}, {"n": 2}, {"n": 3}]));
    }

    #[test]
    fn source_sessions_aggregate_on_the_session_field_the_ip_profile_uses() {
        let body = json!({"size": 0, "query": source_scope("203.0.113.7", "now-7d"), "aggs": session_aggs()});
        assert_eq!(body["aggs"]["sessions"]["terms"]["field"], "honeypot.session");
        assert_eq!(body["aggs"]["session_count"]["cardinality"]["field"], "honeypot.session");
        assert!(rendered(&body["query"]).contains("now-7d"));
    }

    #[test]
    fn source_network_reads_as_and_geo_fields() {
        let body = source_network_body("203.0.113.7");
        assert_eq!(body["aggs"]["asn"]["terms"]["field"], "source.as.asn");
        assert_eq!(body["aggs"]["organization"]["terms"]["field"], "source.as.organization_name");
        assert_eq!(body["aggs"]["provider"]["terms"]["field"], "source.as.type");
        assert_eq!(body["aggs"]["country"]["terms"]["field"], "source.geo.country_iso_code");
    }

    #[test]
    fn asn_takes_a_numeric_term_with_or_without_prefix() {
        assert_eq!(asn_number("51167").unwrap(), 51167);
        assert_eq!(asn_number("AS51167").unwrap(), 51167);
        assert_eq!(asn_number("AS").unwrap_err().0, StatusCode::BAD_REQUEST);
        assert!(rendered(&asn_body(51167)["query"]).contains("\"source.as.asn\":51167"));
    }

    #[test]
    fn session_summary_matches_every_session_id_field() {
        let rendered = rendered(&session_summary_body("abd1cc2740ad")["query"]);
        for field in SESSION_FIELDS {
            assert!(rendered.contains(field), "{field} missing: {rendered}");
        }
    }

    #[test]
    fn payload_delivery_keys_on_the_canonical_payload_hash() {
        let body = payload_delivery_body("4293c1d8");
        assert!(rendered(&body["query"]).contains("\"honeypot.canonical_shasum\":\"4293c1d8\""));
        assert_eq!(body["aggs"]["sources"]["terms"]["field"], "source.ip");
        assert_eq!(body["aggs"]["sessions"]["terms"]["field"], "honeypot.session");
    }

    #[test]
    fn event_drilldowns_read_the_event_indices() {
        // The handlers call state.es.search, which reads this constant.
        assert!(crate::es::EVENT_INDICES.contains(&"honeypot-v2-*"));
        assert!(!crate::es::EVENT_INDICES.iter().any(|index| index.starts_with("events-") || index.starts_with("sessions-")));
    }

    #[test]
    fn an_empty_list_is_200_with_zero_total_not_404() {
        let empty = json!({"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}});
        assert_eq!(list_body(&empty), json!({"total": 0, "rows": []}));
        // An index that does not exist answers with no hits block at all.
        assert_eq!(list_body(&json!({})), json!({"total": 0, "rows": []}));
    }

    #[test]
    fn an_empty_session_list_is_200_with_zero_total() {
        let empty = json!({"aggregations": {"sessions": {"buckets": []}, "session_count": {"value": 0}}});
        assert_eq!(session_list(&empty), json!({"total": 0, "rows": []}));
    }

    // ---- #3532: IOC catalog, IOC detail, entity timeline, related ----------

    fn all_defs() -> Vec<&'static IocKindDef> { IOC_KINDS.iter().collect() }

    #[test]
    fn optional_ranges_default_and_stay_bounded() {
        assert_eq!(range_or(&None, "7d").unwrap(), "now-7d");
        assert_eq!(range_or(&Some("1h".into()), "7d").unwrap(), "now-1h");
        assert_eq!(range_or(&Some("90d".into()), "7d").unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn the_fleet_is_excluded_from_every_scope_by_source_ip() {
        let query = rendered(&ioc_scope(vec![time_range("now-7d")], vec![]));
        assert!(query.contains("\"10.0.0.0/8\"") && query.contains("\"192.168.0.0/16\"") && query.contains("\"fe80::/10\""), "{query}");
        assert!(query.contains("10.8.0.1"), "the tunnel peer is always a self address: {query}");
        assert!(query.contains("\"source.ip\":["), "{query}");
        assert!(query.contains("internal_probe"), "internal probes stay out: {query}");
        assert!(query.contains("\"flow\""), "the explorer's noise exclusion applies: {query}");
    }

    #[test]
    fn secret_kinds_never_read_the_scrubbed_sensors() {
        for name in ["credential", "password"] {
            let def = ioc_kind(name).unwrap();
            let body = catalog_body("now-7d", &[def], None, 5);
            let text = rendered(&body);
            for sensor in crate::secrets_boundary::CREDENTIAL_SENSORS {
                assert!(text.contains(sensor), "{name} must exclude {sensor}: {text}");
            }
            let detail = rendered(&ioc_detail_body(def, "root:x", "now-30d").unwrap());
            assert!(detail.contains("http-honeypot") && detail.contains("cisco-asa-honeypot"), "{detail}");
        }
        // Not secret: a username, a command.
        assert!(!rendered(&catalog_body("now-7d", &[ioc_kind("username").unwrap()], None, 5)).contains("http-honeypot"));
        assert!(!ioc_extra_must_not(ioc_kind("command").unwrap()).iter().any(|c| c.to_string().contains("http-honeypot")));
    }

    #[test]
    fn the_catalog_aggregates_each_kind_on_its_own_field() {
        let body = catalog_body("now-7d", &all_defs(), None, 7);
        let aggs = &body["aggs"];
        assert_eq!(body["size"], 0);
        assert_eq!(aggs["hash__0"]["aggs"]["v"]["terms"]["field"], "honeypot.canonical_shasum");
        assert_eq!(aggs["hash__0"]["aggs"]["v"]["terms"]["size"], 7);
        assert_eq!(aggs["url__0"]["aggs"]["v"]["terms"]["field"], "honeypot.url");
        assert_eq!(aggs["command__0"]["aggs"]["v"]["terms"]["field"], "honeypot.canonical_command");
        assert_eq!(aggs["username__0"]["aggs"]["v"]["terms"]["field"], "honeypot.canonical_user");
        assert_eq!(aggs["password__0"]["aggs"]["v"]["terms"]["field"], "honeypot.canonical_pass");
        assert_eq!(aggs["fingerprint__0"]["aggs"]["v"]["terms"]["field"], "honeypot.canonical_fingerprint");
        // Suricata strings are text; only the .keyword sub-field aggregates.
        assert_eq!(aggs["signature__0"]["aggs"]["v"]["terms"]["field"], "suricata.eve.alert.signature.keyword");
        assert_eq!(aggs["cve__0"]["aggs"]["v"]["terms"]["field"], "honeypot.cve");
        assert_eq!(aggs["cve__1"]["aggs"]["v"]["terms"]["field"], "suricata.eve.alert.metadata.cve.keyword");
        assert_eq!(aggs["credential__0"]["aggs"]["v"]["multi_terms"]["terms"][0]["field"], "honeypot.canonical_user");
        assert_eq!(aggs["credential__0"]["aggs"]["v"]["multi_terms"]["terms"][1]["field"], "honeypot.canonical_pass");
        // domains are DNS-decoy queries, not any `query` field (http-honeypot's is a URL query string).
        assert!(rendered(&aggs["domain__0"]["filter"]).contains("dns-honeypot"));
        for name in aggs.as_object().unwrap().keys() {
            for stat in ["first", "last", "sources", "sources_fb", "sessions"] {
                assert!(aggs[name]["aggs"]["v"]["aggs"].get(stat).is_some(), "{name} lacks {stat}");
            }
        }
    }

    #[test]
    fn protocol_banners_are_not_fingerprint_indicators() {
        let body = catalog_body("now-7d", &[ioc_kind("fingerprint").unwrap()], None, 5);
        assert!(rendered(&body["aggs"]["fingerprint__0"]["filter"]).contains("client banner"));
        let clause = rendered(&ioc_value_clause(ioc_kind("fingerprint").unwrap(), "RFB 003.008").unwrap());
        assert!(clause.contains("client banner"), "{clause}");
    }

    #[test]
    fn catalog_q_is_a_case_insensitive_escaped_substring() {
        assert_eq!(wildcard_escape("a*b?c\\d"), "a\\*b\\?c\\\\d");
        let body = catalog_body("now-7d", &[ioc_kind("command").unwrap()], Some("wget*"), 5);
        let filter = rendered(&body["aggs"]["command__0"]["filter"]);
        assert!(filter.contains("*wget\\\\*") || filter.contains("wget\\*"), "{filter}");
        assert!(filter.contains("\"case_insensitive\":true"), "{filter}");
        let credential = rendered(&catalog_body("now-7d", &[ioc_kind("credential").unwrap()], Some("root"), 5)["aggs"]["credential__0"]["filter"]);
        assert!(credential.contains("honeypot.canonical_user") && credential.contains("honeypot.canonical_pass"), "{credential}");
    }

    #[test]
    fn cve_ids_are_normalised_and_matched_in_both_spellings() {
        assert_eq!(normalize_cve("CVE_2025_29927"), "CVE-2025-29927");
        assert_eq!(normalize_cve(" cve-2026-24061 "), "CVE-2026-24061");
        assert_eq!(cve_variants("CVE-2025-29927"), vec!["CVE-2025-29927", "CVE_2025_29927"]);
        let clause = rendered(&ioc_value_clause(ioc_kind("cve").unwrap(), "cve_2025_29927").unwrap());
        assert!(clause.contains("CVE_2025_29927") && clause.contains("CVE-2025-29927"), "{clause}");
        assert!(clause.contains("honeypot.cve") && clause.contains("suricata.eve.alert.metadata.cve.keyword"), "{clause}");
    }

    #[test]
    fn credential_values_split_on_the_first_colon_and_allow_one_empty_side() {
        let def = ioc_kind("credential").unwrap();
        let both = rendered(&ioc_value_clause(def, "root:pa:ss").unwrap());
        assert!(both.contains("\"honeypot.canonical_user\":\"root\"") && both.contains("\"honeypot.canonical_pass\":\"pa:ss\""), "{both}");
        let password_only = rendered(&ioc_value_clause(def, ":hunter2").unwrap());
        assert!(password_only.contains("\"honeypot.canonical_pass\":\"hunter2\"") && password_only.contains("must_not"), "{password_only}");
        assert_eq!(ioc_value_clause(def, ":").unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn domain_values_only_match_the_dns_decoy() {
        let clause = rendered(&ioc_value_clause(ioc_kind("domain").unwrap(), "example.org").unwrap());
        assert!(clause.contains("\"honeypot.query\":\"example.org\"") && clause.contains("dns-honeypot"), "{clause}");
    }

    #[test]
    fn unknown_kinds_are_not_defined() {
        assert!(ioc_kind("nonsense").is_none());
        assert_eq!(IOC_KINDS.len(), 10);
        for name in ["hash", "domain", "url", "credential", "command", "fingerprint", "cve", "signature", "username", "password"] {
            assert!(ioc_kind(name).is_some(), "{name}");
        }
    }

    fn catalog_result() -> Value {
        json!({"aggregations": {
            "cve__0": {"doc_count": 2, "v": {"sum_other_doc_count": 0, "buckets": [
                {"key": "CVE-2026-24061", "doc_count": 4, "sources": {"value": 1}, "sessions": {"value": 3},
                 "first": {"value_as_string": "2026-10-02T00:00:00.000Z"}, "last": {"value_as_string": "2026-10-03T00:00:00.000Z"}}]}},
            "cve__1": {"doc_count": 9, "v": {"sum_other_doc_count": 5, "buckets": [
                {"key": "CVE_2026_24061", "doc_count": 6, "sources": {"value": 4}, "sessions": {"value": 0},
                 "first": {"value_as_string": "2026-10-01T00:00:00.000Z"}, "last": {"value_as_string": "2026-10-02T12:00:00.000Z"}},
                {"key": "CVE_1999_0517", "doc_count": 3, "sources": {"value": 2}, "sessions": {"value": 0}}]}},
            "credential__0": {"doc_count": 3, "v": {"sum_other_doc_count": 0, "buckets": [
                {"key": ["root", "toor"], "doc_count": 3, "sources": {"value": 1, "sources_fb": {}}, "sessions": {"value": 1}},
                {"key": ["", "hunter2"], "doc_count": 2, "sources": {"value": 1}, "sessions": {"value": 1}},
                {"key": ["", ""], "doc_count": 9, "sources": {"value": 1}, "sessions": {"value": 1}}]}},
            "hash__0": {"doc_count": 0, "v": {"buckets": []}}
        }})
    }

    #[test]
    fn catalog_rows_merge_the_two_cve_fields_by_normalised_value() {
        let (rows, truncated) = catalog_rows(&catalog_result(), ioc_kind("cve").unwrap(), 10);
        assert!(truncated, "ES reported buckets beyond the requested size");
        assert_eq!(rows.len(), 2);
        let merged = &rows[0];
        assert_eq!(merged.value, "CVE-2026-24061");
        assert_eq!(merged.events, 10, "events add across the two fields");
        assert_eq!(merged.sources, 4, "sources take the larger count");
        assert_eq!(merged.sessions, 3);
        assert_eq!(merged.first_seen.as_deref(), Some("2026-10-01T00:00:00.000Z"));
        assert_eq!(merged.last_seen.as_deref(), Some("2026-10-03T00:00:00.000Z"));
        assert_eq!(rows[1].value, "CVE-1999-0517");
    }

    #[test]
    fn catalog_credentials_are_user_colon_password_and_skip_empty_pairs() {
        let (rows, _) = catalog_rows(&catalog_result(), ioc_kind("credential").unwrap(), 10);
        let values: Vec<&str> = rows.iter().map(|row| row.value.as_str()).collect();
        assert_eq!(values, vec!["root:toor", ":hunter2"]);
    }

    #[test]
    fn catalog_rows_are_cut_to_size_and_flagged() {
        let (rows, truncated) = catalog_rows(&catalog_result(), ioc_kind("cve").unwrap(), 1);
        assert_eq!(rows.len(), 1);
        assert!(truncated);
    }

    #[test]
    fn catalog_response_has_every_kind_and_names_truncated_ones() {
        let defs = all_defs();
        let body = catalog_response(&catalog_result(), &defs, "now-7d", 10);
        assert_eq!(body["range"], "7d");
        let kinds = body["kinds"].as_object().unwrap();
        assert_eq!(kinds.len(), 10);
        assert_eq!(kinds["hash"], json!([]), "a kind with nothing seen is an empty list, not missing");
        assert_eq!(body["truncated"], json!(["cve"]));
        let first = &kinds["cve"][0];
        assert_eq!(first["id"], "cve:CVE-2026-24061");
        assert_eq!(first["kind"], "cve");
        for key in ["value", "events", "sources", "sessions", "first_seen", "last_seen"] {
            assert!(first.get(key).is_some(), "{key}");
        }
    }

    #[test]
    fn a_single_kind_catalog_leaves_the_rest_empty() {
        let only = vec![ioc_kind("credential").unwrap()];
        let body = catalog_response(&catalog_result(), &only, "now-24h", 10);
        assert_eq!(body["kinds"]["cve"], json!([]));
        assert_eq!(body["kinds"]["credential"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn ioc_detail_queries_the_value_in_range_and_aggregates_bounded_lists() {
        let body = ioc_detail_body(ioc_kind("command").unwrap(), "enable", "now-30d").unwrap();
        let query = rendered(&body["query"]);
        assert!(query.contains("\"honeypot.canonical_command\":\"enable\"") && query.contains("now-30d"), "{query}");
        assert_eq!(body["size"], 20);
        assert_eq!(body["sort"][0]["@timestamp"]["order"], "desc");
        assert_eq!(body["aggs"]["sessions"]["terms"]["size"], 20);
        assert_eq!(body["aggs"]["sources"]["terms"]["field"], "source.ip");
        assert_eq!(body["aggs"]["payloads"]["terms"]["field"], "honeypot.canonical_shasum");
        assert!(body["aggs"].get("sources_fb").is_some() && body["aggs"].get("count_sources").is_some());
        assert!(body["aggs"].get("SOURCE_AGGS").is_none());
    }

    #[test]
    fn related_session_payloads_search_every_session_field() {
        let body = session_payloads_body(&["abc".into(), "def".into()], "now-7d");
        let query = rendered(&body["query"]);
        for field in SESSION_FIELDS {
            assert!(query.contains(field), "{field}: {query}");
        }
        assert_eq!(body["aggs"]["payloads"]["terms"]["field"], "honeypot.canonical_shasum");
    }

    #[test]
    fn ioc_detail_response_is_a_flat_documented_shape() {
        let result = json!({
            "hits": {"total": {"value": 3}, "hits": [{"_id": "e1", "_source": {
                "@timestamp": "2026-10-09T10:00:00Z", "event": {"sensor": "cowrie"}, "source": {"ip": "203.0.113.7"},
                "honeypot": {"eventid": "cowrie.command.input", "input": "uname -a", "session": "s1"}}}]},
            "aggregations": {
                "first": {"value_as_string": "2026-10-01T00:00:00.000Z"}, "last": {"value_as_string": "2026-10-09T10:00:00.000Z"},
                "sensors": {"buckets": [{"key": "cowrie", "doc_count": 3}]},
                "sources": {"buckets": [{"key": "203.0.113.7", "doc_count": 2}]},
                "sources_fb": {"f0": {"buckets": [{"key": "198.51.100.9", "doc_count": 1}]}, "f1": {"buckets": []}},
                "count_sources": {"value": 1}, "count_sources_fb": {"f0": {"v": {"value": 2}}, "f1": {"v": {"value": 0}}},
                "sessions": {"buckets": [{"key": "s1", "doc_count": 3, "first": {"value_as_string": "a"}, "last": {"value_as_string": "b"}}]},
                "session_count": {"value": 1}
            }
        });
        let body = ioc_detail_response(ioc_kind("command").unwrap(), "uname -a", "now-30d", &result, vec![json!({"key": "abc", "count": 1})]);
        assert_eq!(body["id"], "command:uname -a");
        assert_eq!(body["range"], "30d");
        assert_eq!(body["events"], 3);
        assert_eq!(body["sources_total"], 2, "the larger of the source.ip and fallback address counts");
        assert_eq!(body["sessions_total"], 1);
        assert_eq!(body["sensors"], json!([{"key": "cowrie", "count": 3}]));
        assert_eq!(body["sources"], json!([{"key": "203.0.113.7", "count": 2}, {"key": "198.51.100.9", "count": 1}]));
        assert_eq!(body["sessions"][0], json!({"session": "s1", "events": 3, "first": "a", "last": "b"}));
        assert_eq!(body["payloads"][0]["key"], "abc");
        let event = &body["recent_events"][0];
        assert_eq!(event["id"], "e1");
        assert_eq!(event["src_ip"], "203.0.113.7");
        assert_eq!(event["kind"], "command");
        assert!(event.get("record").is_none(), "no raw _source dump");
    }

    #[test]
    fn detail_events_for_a_scrubbed_sensor_carry_no_password() {
        let hit = json!({"_id": "x", "_source": {
            "@timestamp": "2026-10-09T10:00:00Z", "event": {"sensor": "http-honeypot"}, "source": {"ip": "203.0.113.7"},
            "honeypot": {"event": "http_request", "method": "POST", "path": "/login", "username": "admin", "password": "hunter2", "body": "user=admin&password=hunter2"}}});
        let text = event_summary(&hit).to_string();
        assert!(!text.contains("hunter2"), "{text}");
    }

    // entity ids

    #[test]
    fn entity_ids_parse_by_prefix() {
        assert_eq!(parse_entity("ip:203.0.113.7").unwrap(), Entity::Ip("203.0.113.7".into()));
        assert_eq!(parse_entity("source:2001:db8::1").unwrap(), Entity::Ip("2001:db8::1".into()));
        assert_eq!(parse_entity("cidr:203.0.113.0/24").unwrap(), Entity::Cidr("203.0.113.0/24".into()));
        assert_eq!(parse_entity("network:203.0.113.0/24").unwrap(), Entity::Cidr("203.0.113.0/24".into()));
        assert_eq!(parse_entity("asn:AS13335").unwrap(), Entity::Asn(13335));
        assert_eq!(parse_entity("session:abd1cc2740ad").unwrap(), Entity::Session("abd1cc2740ad".into()));
        assert_eq!(parse_entity("payload:ABCDEF").unwrap(), Entity::Payload("abcdef".into()));
        assert_eq!(parse_entity("hash:ab").unwrap(), Entity::Payload("ab".into()));
        assert_eq!(parse_entity("identity:e69").unwrap(), Entity::Identity { id: "e69".into(), ips: vec![] });
        assert_eq!(parse_entity("campaign:203.0.113.0/24").unwrap(), Entity::Campaign("203.0.113.0/24".into()));
        assert_eq!(parse_entity("cluster:fingerprint:JA4:t13").unwrap(), Entity::Cluster { kind: "fingerprint".into(), value: "JA4:t13".into() });
        assert_eq!(parse_entity("ioc:credential:root:toor").unwrap(), Entity::Ioc { kind: "credential".into(), value: "root:toor".into() });
    }

    #[test]
    fn bare_entity_ids_are_inferred() {
        assert_eq!(parse_entity("203.0.113.7").unwrap(), Entity::Ip("203.0.113.7".into()));
        assert_eq!(parse_entity("2001:db8::1").unwrap(), Entity::Ip("2001:db8::1".into()));
        assert_eq!(parse_entity("203.0.113.0/24").unwrap(), Entity::Cidr("203.0.113.0/24".into()));
        assert_eq!(parse_entity("AS13335").unwrap(), Entity::Asn(13335));
        assert_eq!(parse_entity("as13335").unwrap(), Entity::Asn(13335));
        let sha = "4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7";
        assert_eq!(parse_entity(sha).unwrap(), Entity::Payload(sha.into()));
        assert_eq!(parse_entity("abd1cc2740ad").unwrap(), Entity::Session("abd1cc2740ad".into()));
    }

    #[test]
    fn malformed_entity_ids_are_400() {
        for bad in ["", "ip:", "ip:not-an-ip", "cidr:10.0.0.0/2", "cidr:1.2.3.4/33", "cidr:x/24", "asn:", "asn:ASx", "ioc:nonsense:x", "ioc:hash", "ioc:hash:", "campaign:abc", "mystery:thing"] {
            assert_eq!(parse_entity(bad).unwrap_err().0, StatusCode::BAD_REQUEST, "{bad:?}");
        }
        assert_eq!(parse_entity(&"a".repeat(3000)).unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn entity_ids_round_trip() {
        for id in ["ip:203.0.113.7", "cidr:203.0.113.0/24", "asn:13335", "session:abd1cc2740ad", "payload:abcdef", "identity:e69", "campaign:203.0.113.0/24", "ioc:signature:ET X"] {
            assert_eq!(parse_entity(id).unwrap().id(), id);
        }
        assert_eq!(parse_entity("ip:203.0.113.7").unwrap().kind(), "ip");
    }

    #[test]
    fn cidr_prefixes_are_bounded() {
        assert_eq!(valid_cidr("203.0.113.0/24").as_deref(), Some("203.0.113.0/24"));
        assert_eq!(valid_cidr("2001:db8::/32").as_deref(), Some("2001:db8::/32"));
        assert!(valid_cidr("0.0.0.0/0").is_none());
        assert!(valid_cidr("203.0.113.0/7").is_none());
        assert!(valid_cidr("2001:db8::/16").is_none());
        assert!(valid_cidr("203.0.113.0").is_none());
    }

    #[test]
    fn entity_clauses_hit_the_fields_the_other_routes_use() {
        let ip = rendered(&entity_clause(&Entity::Ip("203.0.113.7".into())));
        assert!(ip.contains("\"source.ip\":\"203.0.113.7\"") && ip.contains("honeypot.src_ip") && ip.contains("honeypot.data.connection.remote_ip"), "{ip}");
        assert!(rendered(&entity_clause(&Entity::Cidr("203.0.113.0/24".into()))).contains("\"source.ip\":\"203.0.113.0/24\""));
        assert!(rendered(&entity_clause(&Entity::Campaign("203.0.113.0/24".into()))).contains("\"source.ip\":\"203.0.113.0/24\""));
        assert!(rendered(&entity_clause(&Entity::Asn(13335))).contains("\"source.as.asn\":13335"));
        let session = rendered(&entity_clause(&Entity::Session("abc".into())));
        for field in SESSION_FIELDS {
            assert!(session.contains(field), "{field}");
        }
        assert!(rendered(&entity_clause(&Entity::Payload("ab".into()))).contains("\"honeypot.canonical_shasum\":\"ab\""));
        assert!(rendered(&entity_clause(&Entity::Identity { id: "i".into(), ips: vec!["203.0.113.7".into()] })).contains("\"source.ip\":[\"203.0.113.7\"]"));
        assert!(rendered(&entity_clause(&Entity::Identity { id: "i".into(), ips: vec![] })).contains("match_none"));
        assert!(rendered(&entity_clause(&Entity::Ioc { kind: "signature".into(), value: "ET X".into() })).contains("suricata.eve.alert.signature.keyword"));
        assert!(rendered(&entity_clause(&Entity::Cluster { kind: "bogus".into(), value: "x".into() })).contains("match_none"));
    }

    #[test]
    fn a_secret_indicator_entity_keeps_the_scrubbed_sensors_out() {
        let entity = Entity::Ioc { kind: "password".into(), value: "hunter2".into() };
        assert!(rendered(&entity_scope(&entity, "now-24h")).contains("cisco-asa-honeypot"));
        assert!(!rendered(&entity_scope(&Entity::Asn(1), "now-24h")).contains("cisco-asa-honeypot"));
    }

    #[test]
    fn store_address_clauses_exist_only_for_address_entities() {
        assert!(entity_ip_clause(&Entity::Ip("203.0.113.7".into()), "src_ip").is_some());
        assert!(entity_ip_clause(&Entity::Cidr("203.0.113.0/24".into()), "src_ip").is_some());
        assert!(entity_ip_clause(&Entity::Identity { id: "i".into(), ips: vec!["203.0.113.7".into()] }, "src_ip").is_some());
        assert!(entity_ip_clause(&Entity::Identity { id: "i".into(), ips: vec![] }, "src_ip").is_none());
        assert!(entity_ip_clause(&Entity::Session("s".into()), "src_ip").is_none());
        assert!(entity_ip_clause(&Entity::Asn(1), "src_ip").is_none());
    }

    #[test]
    fn identity_addresses_drop_fleet_and_garbage() {
        let doc = json!({"ips": ["203.0.113.7", "10.8.0.1", "127.0.0.1", "not-an-ip", "198.51.100.1"], "credentials": ["root / hunter2"]});
        assert_eq!(identity_ips(&doc), vec!["203.0.113.7", "198.51.100.1"]);
        assert!(identity_ips(&json!({})).is_empty());
    }

    // timeline

    #[test]
    fn timeline_events_are_newest_first_bounded_and_scoped() {
        let body = timeline_events_body(&Entity::Ip("203.0.113.7".into()), "now-24h", 50);
        assert_eq!(body["size"], 50);
        assert_eq!(body["sort"][0]["@timestamp"]["order"], "desc");
        let query = rendered(&body["query"]);
        assert!(query.contains("203.0.113.7") && query.contains("now-24h") && query.contains("10.0.0.0/8"), "{query}");
    }

    #[test]
    fn timeline_ml_matches_the_address_or_the_event_ids_and_never_the_fleet() {
        let body = timeline_ml_body(&Entity::Ip("203.0.113.7".into()), "now-7d", 20, &["e1".into(), "e2".into()]).unwrap();
        let query = rendered(&body["query"]);
        assert!(query.contains("\"src_ip\":\"203.0.113.7\"") && query.contains("\"source_event_id\":[\"e1\",\"e2\"]"), "{query}");
        assert!(query.contains("10.0.0.0/8") && query.contains("10.8.0.1"), "{query}");
        // An ASN entity can only match through its events.
        assert!(timeline_ml_body(&Entity::Asn(1), "now-7d", 20, &[]).is_none());
        let by_events = timeline_ml_body(&Entity::Asn(1), "now-7d", 20, &["e1".into()]).unwrap();
        assert!(!rendered(&by_events).contains("\"src_ip\":\""));
    }

    #[test]
    fn timeline_llm_matches_address_sessions_and_payload() {
        let ip = rendered(&timeline_llm_body(&Entity::Ip("203.0.113.7".into()), "now-7d", 20, &["s1".into()]).unwrap());
        assert!(ip.contains("\"src_ip\":\"203.0.113.7\"") && ip.contains("\"session_id\":[\"s1\"]"), "{ip}");
        let payload = rendered(&timeline_llm_body(&Entity::Payload("ab".into()), "now-7d", 20, &[]).unwrap());
        assert!(payload.contains("\"payload_sha256\":\"ab\""), "{payload}");
        assert!(timeline_llm_body(&Entity::Asn(1), "now-7d", 20, &[]).is_none());
    }

    #[test]
    fn event_hits_become_typed_timeline_items() {
        let alert = json!({"_id": "a1", "_source": {"@timestamp": "2026-10-09T10:00:00.000Z", "event": {"sensor": "suricata", "category": "alert"},
            "source": {"ip": "203.0.113.7"}, "suricata": {"eve": {"alert": {"signature": "ET DROP Dshield", "severity": 2, "category": "x"}}}}});
        let item = event_item(&alert).unwrap();
        assert_eq!((item["kind"].as_str(), item["title"].as_str(), item["severity"].as_str()), (Some("alert"), Some("ET DROP Dshield"), Some("medium")));
        assert_eq!(item["href"], "/events/a1");
        assert_eq!(item["detail"], "203.0.113.7 · suricata");

        let capture = json!({"_id": "c1", "_source": {"@timestamp": "2026-10-09T10:00:01Z", "event": {"sensor": "cowrie"},
            "honeypot": {"eventid": "cowrie.session.file_download", "canonical_shasum": "4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7"}}});
        let item = event_item(&capture).unwrap();
        assert_eq!(item["kind"], "capture");
        assert_eq!(item["title"], "Payload captured: 4293c1d8574dc87c…");
        assert_eq!(item["href"], "/payloads/4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7");

        let canary = json!({"_id": "k1", "_source": {"@timestamp": "2026-10-09T10:00:02Z", "event": {"sensor": "canarytokens"},
            "source": {"ip": "203.0.113.9"}, "honeypot": {"memo": "pdf", "token_type": "adobe_pdf"}}});
        let item = event_item(&canary).unwrap();
        assert_eq!((item["kind"].as_str(), item["severity"].as_str()), (Some("canary"), Some("critical")));

        let login = json!({"_id": "l1", "_source": {"@timestamp": "2026-10-09T10:00:03Z", "event": {"sensor": "cowrie"}, "network": {"protocol": "ssh"},
            "source": {"ip": "203.0.113.7", "port": 4000}, "honeypot": {"eventid": "cowrie.login.failed", "username": "root"}}});
        let item = event_item(&login).unwrap();
        assert_eq!(item["kind"], "event");
        assert!(item["detail"].as_str().unwrap().starts_with("203.0.113.7 · cowrie"));
        assert!(event_item(&json!({"_id": "x", "_source": {}})).is_none(), "a hit without a timestamp is skipped");
    }

    #[test]
    fn ml_and_llm_documents_become_timeline_items() {
        let ml = json!({"_id": "m1", "_source": {"@timestamp": "2026-09-29T21:04:06.165Z", "composite_score": 0.8647, "severity": "high",
            "explanation": "Port scan: 4980 unique ports.", "status": "open"}});
        let item = ml_item(&ml).unwrap();
        assert_eq!(item["kind"], "anomaly");
        assert_eq!(item["title"], "Port scan: 4980 unique ports.");
        assert_eq!(item["detail"], "ML score 0.86 · open");
        assert_eq!(item["severity"], "high");
        assert_eq!(item["href"], "/ml-anomalies/m1");
        let llm = json!({"_id": "session-abc", "_source": {"@timestamp": "2026-09-05T14:44:03.509434Z", "summary": "Downloaded a payload.", "intent": "payload-deployment", "severity": "critical"}});
        let item = llm_item(&llm).unwrap();
        assert_eq!((item["kind"].as_str(), item["detail"].as_str(), item["severity"].as_str()), (Some("llm"), Some("AI-generated · payload-deployment"), Some("critical")));
        assert_eq!(item["href"], "/llm-analysis/session-abc");
        let bare = ml_item(&json!({"_id": "m2", "_source": {"@timestamp": "2026-09-29T21:04:06Z", "severity": "weird"}})).unwrap();
        assert!(bare["severity"].is_null(), "an unknown severity word is not passed through");
        assert_eq!(llm_item(&json!({"_id": "l", "_source": {"@timestamp": "2026-01-01T00:00:00Z"}})).unwrap()["title"], "(no summary)");
    }

    #[test]
    fn the_merged_timeline_orders_by_instant_not_by_string() {
        // 10:00:00Z sorts after 10:00:00.5Z as a string ('Z' > '.'), but is earlier.
        let items = vec![
            json!({"id": "a", "at": "2026-10-09T10:00:00Z"}),
            json!({"id": "b", "at": "2026-10-09T10:00:00.500Z"}),
            json!({"id": "c", "at": "2026-10-09T09:00:00.000000Z"}),
            json!({"id": "d", "at": "2026-10-09T11:00:00Z"}),
        ];
        let (total, merged) = merge_timeline(items, 3);
        assert_eq!(total, 4);
        let ids: Vec<&str> = merged.iter().map(|item| item["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["d", "b", "a"]);
    }

    #[test]
    fn the_timeline_document_merges_the_three_stores() {
        let events = json!({"hits": {"hits": [{"_id": "e1", "_source": {"@timestamp": "2026-10-09T10:00:00Z", "event": {"sensor": "cowrie"}, "source": {"ip": "203.0.113.7"}, "honeypot": {"eventid": "cowrie.session.connect"}}}]}});
        let ml = json!({"hits": {"hits": [{"_id": "m1", "_source": {"@timestamp": "2026-10-09T11:00:00Z", "explanation": "x"}}]}});
        let body = timeline_response(&Entity::Ip("203.0.113.7".into()), "now-24h", 100, &events, &ml, &Value::Null);
        assert_eq!(body["id"], "ip:203.0.113.7");
        assert_eq!(body["entity"], json!({"kind": "ip", "value": "203.0.113.7"}));
        assert_eq!(body["range"], "24h");
        assert_eq!(body["total"], 2);
        assert_eq!(body["items"][0]["kind"], "anomaly");
        assert_eq!(body["items"][1]["kind"], "event");
        let empty = timeline_response(&Entity::Asn(1), "now-1h", 10, &json!({}), &Value::Null, &Value::Null);
        assert_eq!((empty["total"].clone(), empty["items"].clone()), (json!(0), json!([])));
    }

    #[test]
    fn hit_sessions_read_every_session_field_once() {
        let hits = vec![
            json!({"_id": "1", "_source": {"honeypot": {"session": "s1"}}}),
            json!({"_id": "2", "_source": {"honeypot": {"session_id": "s2"}}}),
            json!({"_id": "3", "_source": {"session": {"id": "s1"}}}),
            json!({"_id": "4", "_source": {}}),
        ];
        assert_eq!(hit_sessions(&hits), vec!["s1", "s2"]);
        assert_eq!(hit_ids(&hits), vec!["1", "2", "3", "4"]);
    }

    // related

    #[test]
    fn subnets_group_v4_by_24_and_v6_by_64() {
        assert_eq!(subnet_of("203.0.113.77").as_deref(), Some("203.0.113.0/24"));
        assert_eq!(subnet_of("2001:db8:1:2:3::9").as_deref(), Some("2001:db8:1:2::/64"));
        assert!(subnet_of("nope").is_none());
        let rows = subnet_counts(&[("203.0.113.1".into(), 5), ("203.0.113.2".into(), 7), ("198.51.100.1".into(), 20)]);
        assert_eq!(rows, vec![("198.51.100.0/24".to_string(), 20, 1), ("203.0.113.0/24".to_string(), 12, 2)]);
    }

    #[test]
    fn related_stage_one_aggregates_every_pivot_on_the_entity_events() {
        let body = related_scope_body(&Entity::Session("abc".into()), "now-7d");
        assert_eq!(body["size"], 0);
        let aggs = &body["aggs"];
        assert_eq!(aggs["payloads"]["terms"]["field"], "honeypot.canonical_shasum");
        assert_eq!(aggs["asns"]["terms"]["field"], "source.as.asn");
        assert_eq!(aggs["sessions"]["terms"]["field"], "honeypot.session");
        assert_eq!(aggs["credentials"]["aggs"]["v"]["multi_terms"]["terms"][0]["field"], "honeypot.canonical_user");
        assert!(rendered(&aggs["credentials"]["filter"]).contains("http-honeypot"), "scrubbed sensors never contribute credentials");
        assert_eq!(aggs["signatures"]["terms"]["field"], "suricata.eve.alert.signature.keyword");
        assert_eq!(aggs["suricata_cves"]["terms"]["field"], "suricata.eve.alert.metadata.cve.keyword");
        assert_eq!(aggs["sources"]["terms"]["field"], "source.ip");
        assert_eq!(aggs["addresses"]["terms"]["size"], 200);
        assert!(aggs.get("sources_fb").is_some(), "rows without source.ip are counted through the fallback fields");
        assert!(rendered(&aggs["fingerprints"]["filter"]).contains("client banner"));
        assert!(rendered(&body["query"]).contains("abc"));
    }

    fn scope_result() -> Value {
        json!({"aggregations": {
            "sources": {"buckets": [{"key": "203.0.113.7", "doc_count": 30}, {"key": "203.0.113.9", "doc_count": 3}]},
            "sources_fb": {"f0": {"buckets": [{"key": "198.51.100.4", "doc_count": 2}]}, "f1": {"buckets": []}},
            "addresses": {"buckets": [{"key": "203.0.113.7", "doc_count": 30}, {"key": "203.0.113.9", "doc_count": 3}]},
            "addresses_fb": {"f0": {"buckets": []}, "f1": {"buckets": []}},
            "sessions": {"buckets": [{"key": "s1", "doc_count": 5, "last": {"value_as_string": "2026-10-09T10:00:00Z"}}, {"key": "s2", "doc_count": 1}]},
            "payloads": {"buckets": [{"key": "aaaa", "doc_count": 4}, {"key": "bbbb", "doc_count": 2}]},
            "fingerprints": {"v": {"buckets": [
                {"key": "JA4-abc", "doc_count": 6, "kind": {"buckets": [{"key": "JA4"}]}},
                {"key": "Go-http-client/1.1", "doc_count": 9, "kind": {"buckets": [{"key": "User-Agent"}]}}]}},
            "credentials": {"v": {"buckets": [{"key": ["root", "toor"], "doc_count": 3}, {"key": ["", ""], "doc_count": 8}]}},
            "asns": {"buckets": [{"key": 13335, "doc_count": 33, "org": {"buckets": [{"key": "CLOUDFLARENET"}]}}]},
            "sensors": {"buckets": [{"key": "cowrie", "doc_count": 33}]},
            "commands": {"buckets": [{"key": "uname -a", "doc_count": 2}]},
            "urls": {"buckets": []},
            "signatures": {"buckets": [{"key": "ET X", "doc_count": 1}]},
            "cves": {"buckets": [{"key": "CVE-2026-24061", "doc_count": 1}]},
            "suricata_cves": {"buckets": [{"key": "CVE_2025_29927", "doc_count": 2}]}
        }})
    }

    #[test]
    fn address_aggregations_merge_the_fallback_fields_and_sum_counts() {
        let merged = merged_sources(&scope_result()["aggregations"], "sources", 10);
        assert_eq!(merged, vec![("203.0.113.7".to_string(), 30), ("203.0.113.9".to_string(), 3), ("198.51.100.4".to_string(), 2)]);
        assert_eq!(merged_sources(&scope_result()["aggregations"], "sources", 2).len(), 2);
        let fallback_terms = rendered(&source_terms_aggs("sources", 10)[1].1);
        assert!(fallback_terms.contains("\"exclude\"") && fallback_terms.contains("10.8.0.1"), "the tunnel peer is never listed: {fallback_terms}");
    }

    #[test]
    fn source_totals_take_the_largest_address_count() {
        assert_eq!(source_total(&json!({"sources": {"value": 3}, "sources_fb": {"f0": {"v": {"value": 5}}, "f1": {"v": {"value": 1}}}})), 5);
        assert_eq!(source_total(&json!({})), 0);
        let fallback = rendered(&source_card_aggs()[1].1);
        assert!(fallback.contains("10.8.0.1"), "fleet peer is not a source: {fallback}");
    }

    #[test]
    fn bucket_lists_read_plain_and_multi_term_keys() {
        let credentials = bucket_list(&scope_result(), &["credentials", "v"]);
        let keys: Vec<&str> = credentials.iter().map(|(key, _, _)| key.as_str()).collect();
        assert_eq!(keys, vec!["root:toor"], "the all-empty pair is dropped");
        assert_eq!(bucket_list(&scope_result(), &["asns"])[0].0, "13335");
        assert!(bucket_list(&scope_result(), &["missing"]).is_empty());
    }

    #[test]
    fn stage_one_groups_describe_the_entity_and_leave_itself_out() {
        let groups = scope_groups(&Entity::Ip("203.0.113.7".into()), &scope_result());
        let find = |kind: &str| groups.iter().find(|g| g["kind"] == kind).unwrap()["items"].as_array().unwrap().clone();
        let sources = find("source");
        let ids: Vec<&str> = sources.iter().map(|i| i["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["203.0.113.9", "198.51.100.4"], "an address is not related to itself");
        assert_eq!(sources[0]["count"], 3);
        assert!(sources[0]["reason"].as_str().unwrap().contains("ip:203.0.113.7"));
        assert_eq!(find("asn")[0]["label"], "CLOUDFLARENET");
        assert_eq!(find("network")[0]["id"], "203.0.113.0/24");
        assert_eq!(find("network")[0]["note"], "2 addresses");
        assert_eq!(find("credential")[0]["id"], "root:toor");
        assert_eq!(find("fingerprint")[0]["note"], "JA4");
        assert_eq!(find("session")[0]["note"], "5 events · last 2026-10-09T10:00:00Z");
        assert_eq!(find("cve").iter().map(|i| i["id"].as_str().unwrap()).collect::<Vec<_>>(), vec!["CVE-2026-24061", "CVE-2025-29927"]);
        // A session does not list itself, a payload does not list itself, an ASN does not list itself.
        let own = |entity: Entity, kind: &str| scope_groups(&entity, &scope_result()).iter().find(|g| g["kind"] == kind).unwrap()["items"].as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(own(Entity::Session("s1".into()), "session"), vec!["s2"]);
        assert_eq!(own(Entity::Payload("aaaa".into()), "payload"), vec!["bbbb"]);
        assert!(own(Entity::Asn(13335), "asn").is_empty());
        assert!(own(Entity::Cidr("203.0.113.0/24".into()), "network").is_empty());
    }

    #[test]
    fn shared_pivots_skip_noisy_fingerprints_and_the_entitys_own_payload() {
        let ip = shared_pivots(&Entity::Ip("203.0.113.7".into()), &scope_result());
        assert_eq!(ip.payloads, vec!["aaaa", "bbbb"]);
        assert_eq!(ip.fingerprints, vec!["JA4-abc"], "a generic User-Agent says nothing");
        assert_eq!(ip.credentials, vec![("root".to_string(), "toor".to_string())]);
        assert_eq!(ip.subnet.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(ip.asn, Some(13335));
        let payload = shared_pivots(&Entity::Payload("aaaa".into()), &scope_result());
        assert!(payload.payloads.is_empty());
        assert!(payload.subnet.is_none() && payload.asn.is_none(), "same /24 and AS are only asked of an address");
    }

    #[test]
    fn stage_two_looks_for_other_sources_outside_the_entity() {
        let entity = Entity::Ip("203.0.113.7".into());
        let pivots = shared_pivots(&entity, &scope_result());
        let body = related_shared_body(&entity, "now-7d", &pivots).unwrap();
        let aggs = &body["aggs"];
        assert!(rendered(&aggs["payload"]["filter"]).contains("aaaa"));
        assert!(rendered(&aggs["fingerprint"]["filter"]).contains("JA4-abc"));
        let credential = rendered(&aggs["credential"]["filter"]);
        assert!(credential.contains("\"honeypot.canonical_user\":\"root\"") && credential.contains("http-honeypot"), "{credential}");
        assert!(rendered(&aggs["subnet"]["filter"]).contains("203.0.113.0/24"));
        assert!(rendered(&aggs["asn"]["filter"]).contains("13335"));
        assert_eq!(aggs["payload"]["aggs"]["v"]["terms"]["field"], "source.ip");
        let query = rendered(&body["query"]);
        let must_not = rendered(&body["query"]["bool"]["must_not"]);
        assert!(must_not.contains("203.0.113.7"), "the entity's own events are excluded: {query}");
        let nothing = SharedPivots { payloads: vec![], fingerprints: vec![], credentials: vec![], subnet: None, asn: None };
        assert!(related_shared_body(&entity, "now-7d", &nothing).is_none());
    }

    #[test]
    fn stage_two_groups_label_each_shared_pivot() {
        let shared = json!({"aggregations": {
            "payload": {"v": {"buckets": [{"key": "198.51.100.1", "doc_count": 4}]}, "v_fb": {"f0": {"buckets": []}, "f1": {"buckets": []}}},
            "subnet": {"v": {"buckets": []}, "v_fb": {"f0": {"buckets": [{"key": "203.0.113.8", "doc_count": 2}]}, "f1": {"buckets": []}}}
        }});
        let groups = shared_groups(&Entity::Ip("203.0.113.7".into()), &shared);
        let by_label = |label: &str| groups.iter().find(|g| g["label"] == label).unwrap()["items"].as_array().unwrap().clone();
        assert_eq!(by_label("Sources delivering the same payload")[0]["id"], "198.51.100.1");
        assert_eq!(by_label("Sources in the same /24")[0]["id"], "203.0.113.8");
        assert!(by_label("Sources in the same AS").is_empty());
        assert!(groups.iter().all(|g| g["kind"] == "source"));
        assert_eq!(shared_groups(&Entity::Ip("203.0.113.7".into()), &Value::Null).len(), 5, "a missing stage two result is empty groups, not a panic");
    }

    #[test]
    fn store_lookups_are_keyed_on_the_documented_fields() {
        let ips = vec!["203.0.113.7".to_string()];
        let identities = related_identities_body(&ips, Some("me"));
        assert!(rendered(&identities["query"]).contains("ips.keyword") && rendered(&identities["query"]).contains("\"ids\""), "{identities}");
        assert_eq!(identities["size"], 10);
        let flows = related_flows_body(&ips, "now-7d");
        assert!(rendered(&flows["query"]).contains("src_ip.keyword") && rendered(&flows["query"]).contains("now-7d"));
        let campaigns = related_campaigns_body(&["203.0.113.0/24".to_string()], None);
        assert!(rendered(&campaigns["query"]).contains("203.0.113.0/24"));
        assert_eq!(related_addresses(&Entity::Ip("203.0.113.7".into()), &Value::Null), ips);
        assert_eq!(related_addresses(&Entity::Asn(1), &scope_result()), vec!["203.0.113.7", "203.0.113.9"]);
    }

    #[test]
    fn identity_flow_and_campaign_hits_become_related_items() {
        let identities = json!({"hits": {"hits": [{"_id": "i1", "_source": {"id": "i1abcdefgh", "ips": ["203.0.113.7", "203.0.113.8"], "events": 9}}]}});
        let items = identity_items(&identities, &["203.0.113.7".to_string()], "ip:203.0.113.7");
        assert_eq!((items[0]["id"].clone(), items[0]["label"].clone(), items[0]["count"].clone(), items[0]["note"].clone()), (json!("i1abcdefgh"), json!("i1abcdef"), json!(1), json!("2 IPs")));
        let flows = json!({"hits": {"hits": [{"_id": "f", "_source": {"community_id": "1:abc=", "src_ip": "203.0.113.7", "dst_ip": "198.51.100.10", "dst_port": 5900, "events": 7, "sensors": ["huginn", "zeek"]}}]}});
        let items = flow_items(&flows, "ip:203.0.113.7");
        assert_eq!(items[0]["id"], "1:abc=");
        assert_eq!(items[0]["count"], 7);
        assert_eq!(items[0]["note"], "203.0.113.7 → 198.51.100.10:5900 · 7 events across huginn, zeek");
        let campaigns = json!({"hits": {"hits": [{"_id": "203.0.113.0/24", "_source": {"cidr": "203.0.113.0/24", "score": 34, "events": 576}}]}});
        let items = campaign_items(&campaigns, "ip:203.0.113.7");
        assert_eq!((items[0]["id"].clone(), items[0]["note"].clone(), items[0]["count"].clone()), (json!("203.0.113.0/24"), json!("score 34"), json!(576)));
        assert!(identity_items(&Value::Null, &[], "x").is_empty() && flow_items(&Value::Null, "x").is_empty() && campaign_items(&Value::Null, "x").is_empty());
    }

    #[test]
    fn the_related_document_drops_empty_groups_and_names_the_entity() {
        let identities = json!({"hits": {"hits": []}});
        let body = related_response(&Entity::Ip("203.0.113.7".into()), "now-7d", &["203.0.113.7".to_string()], [&scope_result(), &Value::Null, &identities, &Value::Null, &Value::Null]);
        assert_eq!(body["id"], "ip:203.0.113.7");
        assert_eq!(body["range"], "7d");
        let groups = body["groups"].as_array().unwrap();
        assert!(!groups.is_empty());
        assert!(groups.iter().all(|g| !g["items"].as_array().unwrap().is_empty()), "no empty group");
        assert!(groups.iter().all(|g| ["kind", "label", "items"].iter().all(|k| g.get(*k).is_some())));
        let item = &groups[0]["items"][0];
        for key in ["id", "label", "note", "count", "reason"] {
            assert!(item.get(key).is_some(), "{key}");
        }
        let nothing = related_response(&Entity::Asn(1), "now-7d", &[], [&json!({}), &Value::Null, &Value::Null, &Value::Null, &Value::Null]);
        assert_eq!(nothing["groups"], json!([]));
    }
}
