//! Small read endpoints backing the detail/drill-down UI (visual pass;
//! the write-path/worker backends live on #1612):
//! - /api/v1/sandbox/{job} and /api/v1/ghidra/{sha} — one analysis doc.
//! - /api/v1/attackers-graph?id= — hub/spoke/overflow node-edge list for
//!   cytoscape, ported from attackers_graph.go (same 60-node cap).
//! - /api/v1/attack-vectors?sensor= — the overview heatmap's per-sensor
//!   companion panel (#471): ports + protocols the sensor saw in 24h.
//! - POST /api/v1/ml-anomalies/ack — ack state keyed by the anomaly doc
//!   _id in dashboard-ml-anomaly-ack-v1 (#913 contract).

use crate::contract;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::trust::{ActorBinding, ActorField};
use crate::AppState;

const GRAPH_MAX_NODES: usize = 60;
const ML_ACK_INDEX: &str = "dashboard-ml-anomaly-ack-v1";
/// The closed lifecycle set #1968 wrote onto the anomaly documents
/// themselves ("open" is a retraction value, not an in-flight disposition,
/// so it is deliberately absent here — see `ml_anomaly_disposition`).
const DISPOSITION_STATUSES: [&str; 3] = ["false_positive", "true_positive", "benign_known"];

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

async fn one_doc(
    state: &AppState,
    index: &str,
    query: Value,
) -> Result<Json<Value>, (StatusCode, String)> {
    let result = state
        .es
        .search_index(&[index], json!({"size": 1, "query": query}))
        .await
        .map_err(bad_gateway)?;
    result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .map(|hit| {
            let mut doc = hit["_source"].clone();
            doc["_doc_id"] = hit["_id"].clone();
            Json(doc)
        })
        .ok_or((StatusCode::NOT_FOUND, "not found".to_string()))
}

#[utoipa::path(
    get,
    path = "/api/v1/sandbox/{job}",
    summary = "One sandbox run.",
    params(
        ("job" = inline(String), Path, description = "Sandbox job id."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn sandbox_run(
    State(state): State<AppState>,
    Path(job): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    one_doc(
        &state,
        "sandbox-analysis-v1",
        json!({"bool": {"should": [
            {"term": {"sandbox.job": job}},
            {"term": {"job": job}}
        ], "minimum_should_match": 1}}),
    )
    .await
}

#[utoipa::path(
    get,
    path = "/api/v1/ghidra/{sha}",
    summary = "One Ghidra analysis run.",
    params(
        ("sha" = inline(contract::AnalysisSha), Path, description = "Payload/analysis subject id, lower-case hex."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn ghidra_run(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let Json(mut doc) = one_doc(&state, "ghidra-analysis-v1", json!({"term": {"file.hash.sha256": &sha}})).await?;
    // #1735: the Floss/Windows-sandbox IOC correlation the Go tier computed
    // in ghidraData() for the viewed row. Folded into this response rather
    // than served from its own route so the detail page keeps its single
    // hydrate fetch. Correlation failure is not detail-page failure — an
    // unreachable sandbox index costs the card, not the whole analysis, so
    // this cannot return Err.
    let correlation = crate::ioc_correlation::correlate(&state, &sha, &doc).await;
    doc["ioc_correlation"] = serde_json::to_value(correlation).unwrap_or(Value::Null);
    Ok(Json(doc))
}

const GHIDRA_CALLGRAPH_MAX_NODES: usize = 200;

#[utoipa::path(
    get,
    path = "/api/v1/ghidra-callgraph/{sha}",
    summary = "The call graph one Ghidra run produced.",
    params(
        ("sha" = inline(contract::AnalysisSha), Path, description = "Payload/analysis subject id, lower-case hex."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// /api/v1/ghidra-callgraph/{sha} — an interactive complement to the
/// static graphviz SVG the detail page already embeds as an <img>, built
/// from the same per-function Callers/Callees cross-reference data
/// (recovered only for the functions the worker's deep-dive budget
/// covered) the static image is assembled from. Ported from
/// ghidra_callgraph.go's buildGhidraCallGraph, same graphNode/graphEdge
/// wire shape ({id,label,kind}/{source,target}) attackers_graph above
/// already uses for /api/v1/attackers-graph — Cytoscape.js on the
/// frontend reads either one identically.
pub async fn ghidra_callgraph(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let result = state
        .es
        .search_index(&["ghidra-analysis-v1"], json!({"size": 1, "query": {"term": {"file.hash.sha256": sha}}}))
        .await
        .map_err(bad_gateway)?;
    let source = result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .map(|hit| hit["_source"].clone())
        .ok_or((StatusCode::NOT_FOUND, "not found".to_string()))?;
    let functions = source["ghidra"]["functions"].as_array().cloned().unwrap_or_default();
    Ok(Json(build_ghidra_callgraph(&functions)))
}

fn non_empty_array(value: &Value) -> bool {
    value.as_array().is_some_and(|values| !values.is_empty())
}

struct GhidraGraphBuilder<'a> {
    by_addr: std::collections::HashMap<&'a str, &'a Value>,
    deepened: std::collections::HashSet<&'a str>,
    nodes: Vec<Value>,
    node_seen: std::collections::HashSet<String>,
    edges: Vec<Value>,
    edge_seen: std::collections::HashSet<(String, String)>,
    truncated: bool,
}

impl GhidraGraphBuilder<'_> {
    /// A leaf referenced from some deepened function's own xref list gets
    /// its label from `fallback_name` (the name that xref entry carried) —
    /// it only gets `by_addr`'s own richer name if this address also
    /// happens to appear as a function in the list in its own right.
    fn add_node(&mut self, addr: &str, fallback_name: &str) {
        if addr.is_empty() || self.node_seen.contains(addr) {
            return;
        }
        if self.nodes.len() >= GHIDRA_CALLGRAPH_MAX_NODES {
            self.truncated = true;
            return;
        }
        self.node_seen.insert(addr.to_string());
        let label = self
            .by_addr
            .get(addr)
            .and_then(|function| function["name"].as_str())
            .filter(|name| !name.is_empty())
            .or_else(|| Some(fallback_name).filter(|name| !name.is_empty()))
            .unwrap_or(addr);
        let kind = if self.deepened.contains(addr) { "function" } else { "leaf" };
        self.nodes.push(json!({"id": addr, "label": label, "kind": kind}));
    }

    fn add_edge(&mut self, from: &str, to: &str) {
        if from.is_empty() || to.is_empty() || from == to || !self.node_seen.contains(from) || !self.node_seen.contains(to) {
            return;
        }
        let key = (from.to_string(), to.to_string());
        if self.edge_seen.contains(&key) {
            return;
        }
        self.edge_seen.insert(key);
        self.edges.push(json!({"source": from, "target": to}));
    }
}

fn build_ghidra_callgraph(functions: &[Value]) -> Value {
    let by_addr: std::collections::HashMap<&str, &Value> =
        functions.iter().filter_map(|function| function["address"].as_str().filter(|addr| !addr.is_empty()).map(|addr| (addr, function))).collect();
    let deepened: std::collections::HashSet<&str> = by_addr
        .iter()
        .filter(|(_, function)| non_empty_array(&function["callers"]) || non_empty_array(&function["callees"]))
        .map(|(addr, _)| *addr)
        .collect();

    let mut graph = GhidraGraphBuilder {
        by_addr,
        deepened,
        nodes: Vec::new(),
        node_seen: std::collections::HashSet::new(),
        edges: Vec::new(),
        edge_seen: std::collections::HashSet::new(),
        truncated: false,
    };

    for function in functions {
        let Some(address) = function["address"].as_str().filter(|addr| !addr.is_empty()) else { continue };
        if !graph.deepened.contains(address) {
            continue;
        }
        graph.add_node(address, function["name"].as_str().unwrap_or(""));
        for caller in function["callers"].as_array().into_iter().flatten() {
            let addr = caller["addr"].as_str().unwrap_or("");
            graph.add_node(addr, caller["name"].as_str().unwrap_or(""));
            graph.add_edge(addr, address);
        }
        for callee in function["callees"].as_array().into_iter().flatten() {
            let addr = callee["addr"].as_str().unwrap_or("");
            graph.add_node(addr, callee["name"].as_str().unwrap_or(""));
            graph.add_edge(address, addr);
        }
    }

    json!({"nodes": graph.nodes, "edges": graph.edges, "truncated": graph.truncated})
}

#[utoipa::path(
    get,
    path = "/api/v1/revdeck/{sha}",
    summary = "One RevDeck analysis run.",
    params(
        ("sha" = inline(contract::AnalysisSha), Path, description = "Payload/analysis subject id, lower-case hex."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// /api/v1/revdeck/{sha} — #1611 workstream E.8: revdeck-analysis-v1 had
/// no detail endpoint at all, so an unconfigured-worker error state (the
/// live audit's own example) rendered as a blank page rather than a
/// visible error. es_importer.rs wraps the raw revdeck output (itself
/// `{exit_status, revdeck: {...}, sha256, ...}`) one level deeper under
/// the source label, doc id `revdeck:{sha256}` (es_importer.rs's doc_id);
/// same nesting attacker_identity.rs's revdeck_verdict already reads.
pub async fn revdeck_run(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let doc = state
        .es
        .get_doc("revdeck-analysis-v1", &format!("revdeck:{sha}"))
        .await
        .map_err(bad_gateway)?
        .ok_or((StatusCode::NOT_FOUND, "not found".to_string()))?;
    Ok(Json(doc["revdeck"].clone()))
}

#[utoipa::path(
    get,
    path = "/api/v1/cape/{sha}",
    summary = "One CAPE analysis run.",
    params(
        ("sha" = inline(contract::AnalysisSha), Path, description = "Payload/analysis subject id, lower-case hex."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// /api/v1/cape/{sha} — one CAPE detonation result, ported from cape.go's
/// capeData. `report` is CAPE's own raw report — tens of thousands of
/// API-call entries per traced process is normal — so it's never shipped
/// whole; only the bounded `report_summary` this handler reduces it to
/// crosses the wire (mirrors cape.go's own capeReportSummary). The full
/// report stays in Elasticsearch for anyone who needs it, same posture
/// Go's page takes ("too large for this page" — Go links to the raw-JSON
/// API route instead).
pub async fn cape_run(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let doc = state
        .es
        .get_doc("cape-analysis-v1", &format!("cape:{sha}"))
        .await
        .map_err(bad_gateway)?
        .ok_or((StatusCode::NOT_FOUND, "not found".to_string()))?;
    let mut result = doc["cape"].clone();
    let summary = summarize_cape_report(&result["report"]);
    if let Some(object) = result.as_object_mut() {
        object.remove("report");
    }
    result["report_summary"] = summary;
    Ok(Json(result))
}

#[utoipa::path(
    get,
    path = "/api/v1/cape/{sha}/raw",
    summary = "The raw CAPE report JSON for one run.",
    params(
        ("sha" = inline(contract::AnalysisSha), Path, description = "Payload/analysis subject id, lower-case hex."),
    ),
    responses(
        (status = 200, description = "The stored report, verbatim.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// /api/v1/cape/{sha}/raw — the untouched result, full report included.
/// A distinct route from cape_run above (not a query flag on it) so the
/// page's own fetch never accidentally pulls the full report in — this is
/// only ever reached by an explicit "download raw report" click.
pub async fn cape_raw(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let doc = state
        .es
        .get_doc("cape-analysis-v1", &format!("cape:{sha}"))
        .await
        .map_err(bad_gateway)?
        .ok_or((StatusCode::NOT_FOUND, "not found".to_string()))?;
    Ok(Json(doc["cape"].clone()))
}

#[utoipa::path(
    get,
    path = "/api/v1/github-analysis/{sha}",
    summary = "One GitHub analysis run.",
    params(
        ("sha" = inline(contract::AnalysisSha), Path, description = "Payload/analysis subject id, lower-case hex."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// /api/v1/github-analysis/{sha} — one publication result, ported from
/// github_analysis.go's githubAnalysisData. Adds two fields the producer
/// scripts never write, computed here the same way Go's dashboard layer
/// does: `requested_by` (looked up from the audit log — this tier has no
/// session of its own, so "who submitted this" only exists as an audit
/// trail) and `view_url` (a validated raw.githubusercontent.com link to
/// the rendered PDF report, when one genuinely exists).
pub async fn github_analysis_run(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let doc = state
        .es
        .get_doc("github-analysis-v1", &format!("github_analysis:{sha}"))
        .await
        .map_err(bad_gateway)?
        .ok_or((StatusCode::NOT_FOUND, "not found".to_string()))?;
    let mut result = doc["github_analysis"].clone();
    result["requested_by"] = json!(requester_for(&state, &sha));
    result["view_url"] = github_analysis_pdf_url(&result).map_or(Value::Null, |url| json!(url));
    Ok(Json(result))
}

/// Mirrors githubAnalysisRequester: the newest queued github_analysis.submit
/// audit entry for this hash, preferring the username over the bare
/// subject — same posture every other actor-attributed field in this
/// crate takes.
fn requester_for(state: &AppState, sha: &str) -> String {
    for event in state.audit.read(500) {
        if event["action"].as_str() != Some("github_analysis.submit") || event["result"].as_str() != Some("queued") {
            continue;
        }
        let first_field = event["fields"].as_array().and_then(|fields| fields.first()).and_then(Value::as_str);
        if !first_field.is_some_and(|field| field.eq_ignore_ascii_case(sha)) {
            continue;
        }
        let username = event["actor_username"].as_str().unwrap_or("");
        return if username.is_empty() { event["actor_subject"].as_str().unwrap_or("").to_string() } else { username.to_string() };
    }
    String::new()
}

/// Mirrors githubAnalysisPDFURL: report_commit (falling back to commit)
/// must be a real 40-hex-char sha, and report_pdf can't escape the
/// repository via ".." or an absolute path — both are producer-controlled
/// strings that become URL path segments, so validated the same way
/// resolve_payload_path treats a worker-written filename before it
/// becomes a filesystem path.
fn github_analysis_pdf_url(row: &Value) -> Option<String> {
    let commit = row["report_commit"]
        .as_str()
        .filter(|value| !value.is_empty())
        .or_else(|| row["commit"].as_str().filter(|value| !value.is_empty()))?;
    let report_pdf = row["report_pdf"].as_str().filter(|value| !value.is_empty())?;
    if !commit_re().is_match(commit) || report_pdf.contains("..") || report_pdf.starts_with('/') {
        return None;
    }
    Some(format!("https://raw.githubusercontent.com/Xore/honeypot/{commit}/{report_pdf}"))
}

fn commit_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^[0-9a-f]{40}$").expect("static commit pattern"))
}

fn summarize_cape_report(report: &Value) -> Value {
    if !report.is_object() {
        return Value::Null;
    }
    let mut summary_keys: Vec<&String> = report["behavior"]["summary"].as_object().into_iter().flatten().map(|(key, _)| key).collect();
    summary_keys.sort();

    let processes: Vec<Value> = report["behavior"]["processes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|process| {
            let call_count = process["calls"].as_array().map_or(0, Vec::len);
            json!({
                "process_id": process["process_id"],
                "process_name": process["process_name"],
                "parent_id": process["parent_id"],
                "module_path": process["module_path"],
                "first_seen": process["first_seen"],
                "call_count": call_count,
            })
        })
        .collect();
    let total_calls: i64 = processes.iter().map(|process| process["call_count"].as_i64().unwrap_or(0)).sum();

    json!({
        "machine": report["info"]["machine"]["label"],
        "package": report["info"]["package"],
        "route": report["info"]["route"],
        "timeout": report["info"]["timeout"],
        "duration": report["info"]["duration"],
        "malscore": report["malscore"],
        "malstatus": report["malstatus"],
        "summary": report["behavior"]["summary"],
        "summary_keys": summary_keys,
        "processes": processes,
        "total_calls": total_calls,
        "payloads": report["CAPE"]["payloads"],
        "configs": report["CAPE"]["configs"],
        "debug_log": report["debug"]["log"],
        "debug_errors": report["debug"]["errors"],
    })
}

#[derive(Deserialize)]
pub struct GraphQuery {
    pub id: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/attackers-graph",
    summary = "The node/edge graph around one attacker entity.",
    params(
        ("id" = inline(Option<String>), Query, description = "Attacker entity id."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn attackers_graph(
    State(state): State<AppState>,
    Query(query): Query<GraphQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let entity = state
        .es
        .search_index(&["attackers-v1"], json!({"size": 1, "query": {"term": {"id": query.id}}}))
        .await
        .map_err(bad_gateway)?;
    let source = entity["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .map(|hit| hit["_source"].clone())
        .ok_or((StatusCode::NOT_FOUND, "no such attacker entity".to_string()))?;
    let ips: Vec<&str> = source["ips"].as_array().into_iter().flatten().filter_map(|v| v.as_str()).collect();

    let hub_id = format!("hub:{}", query.id);
    let hub_label: String = query.id.chars().take(8).collect();
    let mut nodes = vec![json!({"id": hub_id, "label": hub_label, "kind": "hub"})];
    let mut edges = Vec::new();
    let (spokes, overflow) = if ips.len() > GRAPH_MAX_NODES {
        (&ips[..GRAPH_MAX_NODES - 1], ips.len() - (GRAPH_MAX_NODES - 1))
    } else {
        (&ips[..], 0)
    };
    for ip in spokes {
        nodes.push(json!({"id": ip, "label": ip, "kind": "spoke"}));
        edges.push(json!({"source": hub_id, "target": ip}));
    }
    if overflow > 0 {
        let overflow_id = format!("overflow:{}", query.id);
        nodes.push(json!({"id": overflow_id, "label": format!("+{overflow}"), "kind": "overflow"}));
        edges.push(json!({"source": hub_id, "target": overflow_id}));
    }
    Ok(Json(json!({"nodes": nodes, "edges": edges})))
}

#[derive(Deserialize)]
pub struct VectorsQuery {
    pub sensor: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/attack-vectors",
    summary = "Attack vectors for one sensor.",
    params(
        ("sensor" = inline(Option<String>), Query, description = "A specific sensor. Empty, suricata and portbridge are all rejected: those ship to their own index families."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn attack_vectors(
    State(state): State<AppState>,
    Query(query): Query<VectorsQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let sensor = query.sensor.trim();
    // suricata/portbridge ship to their own index families — a query here
    // would silently return empty (same rejection as the Go handler).
    if sensor.is_empty() || sensor == "suricata" || sensor == "portbridge" {
        return Err((StatusCode::BAD_REQUEST, "a specific sensor is required".into()));
    }
    let body = json!({
        "size": 0,
        "query": {"bool": {"filter": [
            {"term": {"event.sensor": sensor}},
            {"range": {"@timestamp": {"gte": "now-24h"}}}
        // #2145: probe docs carry the queried sensor name plus
        // destination.port/network.protocol, so without this clause the
        // fleet's healthchecks inflate the attack-vectors panel.
        ], "must_not": [crate::es::internal_probe_exclusion()]}},
        "aggs": {
            "ports": {"terms": {"field": "destination.port", "size": 12}},
            "protocols": {"terms": {"field": "network.protocol", "size": 12}}
        }
    });
    let result = state
        .es
        .search_index(&["honeypot-v2-*"], body)
        .await
        .map_err(bad_gateway)?;
    let rows = |agg: &str, link_key: &str| -> Vec<Value> {
        result["aggregations"][agg]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|bucket| {
                let key = bucket["key"]
                    .as_str()
                    .map(String::from)
                    .or_else(|| bucket["key"].as_i64().map(|n| n.to_string()))?;
                Some(json!({
                    "key": key,
                    "count": bucket["doc_count"],
                    "link": format!("/events?sensor={sensor}&{link_key}={key}"),
                }))
            })
            .collect()
    };
    Ok(Json(json!({
        "sensor": sensor,
        "ports": rows("ports", "port"),
        "protocols": rows("protocols", "proto"),
    })))
}

#[derive(Deserialize)]
pub struct MlAckBody {
    /// The anomaly document's _id (surfaced as _doc_id on store rows).
    pub key: String,
    pub ack: bool,
    #[serde(default)]
    pub actor: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/ml-anomalies/ack",
    summary = "Acknowledge one ML anomaly.",
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `MlAckBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn ml_anomaly_ack(
    State(state): State<AppState>,
    binding: ActorBinding,
    Json(mut body): Json<MlAckBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    body.actor = binding.bind("actor", ActorField::Username, &body.actor)?;
    if body.key.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "missing anomaly key".into()));
    }
    let record = write_ml_ack(&state, &body.key, body.ack, &body.actor)
        .await
        .map_err(bad_gateway)?;
    Ok(Json(record))
}

/// The one ack-record write path (#913 record shape), shared by the
/// single-row ack above and ack-all below so both write identical records.
async fn write_ml_ack(state: &AppState, key: &str, ack: bool, actor: &str) -> anyhow::Result<Value> {
    let record = json!({
        "Key": key,
        "Acknowledged": ack,
        "AckedBy": actor,
        "AckedAt": chrono::Utc::now().to_rfc3339(),
    });
    state.es.index_doc(ML_ACK_INDEX, key, record.clone()).await?;
    Ok(record)
}

#[derive(Deserialize)]
pub struct MlAckAllBody {
    #[serde(default)]
    pub actor: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/ml-anomalies/stats",
    summary = "Ack statistics.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/ml-anomalies/stats — #2396's exact all-time backlog numbers.
/// The frontend can only see the ack sidecar wholesale and the dispositioned
/// population through paginated windows, so it cannot form the union the
/// honest "Open (all time)" tile needs; this computes it where both halves
/// live. `open` subtracts every anomaly that is either dispositioned on the
/// document or has an Acknowledged=true sidecar record — overlap between the
/// two bookkeeping forms exists in history (#2396's own ack-before-verdict
/// sequences) and is cancelled by set-union rather than assumed away. Both
/// id pulls share the 10000 cap everything else in this file uses, mirroring
/// the ack map's own ceiling; past that size the count under-reports exactly
/// like ack-all's write set does.
pub async fn ml_anomaly_stats(State(state): State<AppState>) -> Result<Json<Value>, (StatusCode, String)> {
    let total_result = state
        .es
        .search_index(
            &["ml-anomalies"],
            json!({"size": 0, "track_total_hits": true, "query": {"match_all": {}}}),
        )
        .await
        .map_err(bad_gateway)?;
    let dispositioned_results = state
        .es
        .search_index(
            &["ml-anomalies"],
            json!({
                "size": 10000,
                "_source": false,
                "query": {"terms": {"status": DISPOSITION_STATUSES}}
            }),
        )
        .await
        .map_err(bad_gateway)?;
    let acks = state
        .es
        .search_index(&[ML_ACK_INDEX], json!({"size": 10000, "query": {"match_all": {}}}))
        .await
        .map_err(bad_gateway)?;
    let total = total_result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let dispositioned: std::collections::HashSet<&str> = dispositioned_results["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| hit["_id"].as_str())
        .collect();
    let acked: std::collections::HashSet<&str> = acks["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|hit| hit["_source"]["Acknowledged"].as_bool() == Some(true))
        .filter_map(|hit| hit["_id"].as_str())
        .collect();
    let union = dispositioned.len().saturating_add(acked.len()).saturating_sub(dispositioned.union(&acked).count());
    Ok(Json(json!({
        "total": total,
        "open": total.saturating_sub(union as u64),
    })))
}

#[utoipa::path(
    post,
    path = "/api/v1/ml-anomalies/ack-all",
    summary = "Acknowledge every open ML anomaly.",
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `MlAckAllBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// POST /api/v1/ml-anomalies/ack-all — #1566's bulk acknowledge, ported
/// from ml_anomaly_ack.go's serveMLAnomalyAckAll: every open anomaly
/// across the full index (not just the page the client has loaded),
/// through the same per-record write path as the single ack so one failed
/// write can't abort the rest. Returns {"changed": N}.
///
/// #2396: "open" is honored where the lifecycle actually lives now — a
/// document carrying an operator verdict from #1968 is not open no matter
/// what its sidecar says, so the bulk sweep never stamps Acknowledged=true
/// onto verdict-bearing documents (which both muddied seen-vs-judged
/// bookkeeping and inflated the acked denominator of the Open tile forever).
pub async fn ml_anomaly_ack_all(
    State(state): State<AppState>,
    binding: ActorBinding,
    Json(mut body): Json<MlAckAllBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    body.actor = binding.bind("actor", ActorField::Username, &body.actor)?;
    let anomalies = state
        .es
        .search_index(
            &["ml-anomalies"],
            json!({
                "size": 10000,
                "_source": false,
                "query": {"bool": {"must_not": [{"terms": {"status": DISPOSITION_STATUSES}}]}}
            }),
        )
        .await
        .map_err(bad_gateway)?;
    let acks = state
        .es
        .search_index(&[ML_ACK_INDEX], json!({"size": 10000, "query": {"match_all": {}}}))
        .await
        .map_err(bad_gateway)?;
    let acked: std::collections::HashSet<&str> = acks["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|hit| hit["_source"]["Acknowledged"].as_bool() == Some(true))
        .filter_map(|hit| hit["_id"].as_str())
        .collect();
    let mut changed = 0u64;
    for hit in anomalies["hits"]["hits"].as_array().into_iter().flatten() {
        let Some(id) = hit["_id"].as_str().filter(|id| !id.is_empty()) else { continue };
        if acked.contains(id) {
            continue;
        }
        if write_ml_ack(&state, id, true, &body.actor).await.is_ok() {
            changed += 1;
        }
    }
    Ok(Json(json!({"changed": changed})))
}

#[utoipa::path(
    get,
    path = "/api/v1/ml-anomalies/acks",
    summary = "The ack ledger.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/ml-anomalies/acks — key → ack record, merged client-side
/// into the anomalies list (mirrors refreshMLAnomalyAcks).
pub async fn ml_anomaly_acks(State(state): State<AppState>) -> Result<Json<Value>, (StatusCode, String)> {
    let result = state
        .es
        .search_index(&[ML_ACK_INDEX], json!({"size": 10000, "query": {"match_all": {}}}))
        .await
        .map_err(bad_gateway)?;
    let mut map = serde_json::Map::new();
    for hit in result["hits"]["hits"].as_array().into_iter().flatten() {
        if let Some(id) = hit["_id"].as_str() {
            map.insert(id.to_string(), hit["_source"].clone());
        }
    }
    Ok(Json(Value::Object(map)))
}

#[derive(Deserialize)]
pub struct MlDispositionBody {
    /// The anomaly document's _id (surfaced as _doc_id on store rows).
    pub key: String,
    /// Closed lifecycle set (#1968). `open` is assignable only as an
    /// explicit retraction — a mis-clicked verdict must be undoable, not
    /// half-survive beside its withdrawn status.
    pub status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub actor: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/ml-anomalies/disposition",
    summary = "Record an analyst disposition for anomalies.",
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `MlDispositionBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// POST /api/v1/ml-anomalies/disposition — #1968's operator verdict, written
/// ONTO the ml-anomalies document itself so the labelled corpus #1794/#1797
/// feed on lives beside the score it judges. Deliberately an `_update`
/// partial (`update_doc`, retry-on-conflict), never a whole-document index:
/// the worker owns every other field and rewrites them wholesale on replay,
/// preserving only the disposition_* fields it reads back first. The legacy
/// ack sidecar index keeps working unchanged alongside this.
pub async fn ml_anomaly_disposition(
    State(state): State<AppState>,
    binding: ActorBinding,
    Json(mut body): Json<MlDispositionBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    body.actor = binding.bind("actor", ActorField::Username, &body.actor)?;
    if body.key.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "missing anomaly key".into()));
    }
    match body.status.as_str() {
        "open" | "false_positive" | "true_positive" | "benign_known" => {}
        other => return Err((StatusCode::BAD_REQUEST, format!("invalid status: {other}"))),
    }
    let doc = if body.status == "open" {
        // Retraction nulls the metadata out (ES keeps explicit nulls, which
        // the worker's read-back then treats as unset) instead of leaving a
        // stale reason and actor beside a withdrawn verdict.
        json!({
            "status": "open",
            "disposition_reason": serde_json::Value::Null,
            "disposition_by": serde_json::Value::Null,
            "disposed_at": serde_json::Value::Null,
        })
    } else {
        json!({
            "status": body.status,
            "disposition_reason": body.reason,
            "disposition_by": body.actor,
            "disposed_at": chrono::Utc::now().to_rfc3339(),
        })
    };
    state
        .es
        .update_doc("ml-anomalies", &body.key, doc)
        .await
        .map_err(bad_gateway)?;
    Ok(Json(json!({
        "key": body.key,
        "status": body.status,
        "disposed_at": chrono::Utc::now().to_rfc3339(),
    })))
}
