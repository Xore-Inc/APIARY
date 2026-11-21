//! Kill-chain analytics (#1224) — the three chart endpoints, JSON shapes
//! identical to the Go tier's /api/kill-chain-sankey, /api/attck-coverage
//! and /api/campaign-timeline so the ported chart builders consume them
//! unchanged. One structural upgrade: instead of re-running
//! intelligence.go's per-event technique heuristics over an in-memory
//! cache, this tier aggregates the ATT&CK technique IDs
//! ip-enrichment-worker already promotes onto documents
//! (honeypot.canonical_attck_techniques, #1197/#1202). #1611 workstream D
//! widened the worker to promote the full technique set directly
//! (T1190/T0886/T1692.001 included, see ip_enrichment/attck.rs) — this
//! used to supplement those three with query-time filter aggregations
//! here (a narrower, flattened-field-safe approximation of
//! dashboard/intelligence.go's own path-substring heuristic); now that a
//! real tag exists on new documents, this is a plain terms aggregation
//! only. Historical documents written before this change won't carry the
//! new tags until reindexed/rolled over — not backfilled by this change.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;

use crate::AppState;

const WINDOW: &str = "now-48h";
const GROUP_CAP: u64 = 1000;

pub const TACTICS: &[&str] = &[
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Credential Access",
    "Lateral Movement",
    "Command and Control",
    "Impair Process Control",
];

/// Shared with rollups.rs, whose worker materializes the same per-hour
/// grouping semantics these endpoints used to compute per request (#2046).
pub(crate) fn tactic_for(technique: &str) -> Option<&'static str> {
    Some(match technique {
        "T1595" => "Reconnaissance",
        "T1190" => "Initial Access",
        "T1059" | "T1059.001" | "T1059.003" | "T1059.004" => "Execution",
        "T1110" => "Credential Access",
        "T0886" => "Lateral Movement",
        "T1105" => "Command and Control",
        "T1692.001" => "Impair Process Control",
        _ => return None,
    })
}

fn technique_name(technique: &str) -> &'static str {
    match technique {
        "T1595" => "Active Scanning",
        "T1190" => "Exploit Public-Facing Application",
        "T1059" => "Command and Scripting Interpreter",
        "T1059.001" => "PowerShell",
        "T1059.003" => "Windows Command Shell",
        "T1059.004" => "Unix Shell",
        "T1110" => "Brute Force",
        "T0886" => "Remote Services",
        "T1105" => "Ingress Tool Transfer",
        "T1692.001" => "Unauthorized Message: Command Message",
        _ => "",
    }
}

pub(crate) fn tactic_index(tactic: &str) -> usize {
    TACTICS.iter().position(|candidate| *candidate == tactic).unwrap_or(usize::MAX)
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

/// Technique → count over the recent window: a plain terms aggregation on
/// the worker-promoted tag. #1611 workstream D removed the three
/// query-time supplemental filter aggregations this used to also run
/// (ICS/ICS-write/web-exploit) now that ip-enrichment-worker promotes
/// T0886/T1692.001/T1190 directly onto canonical_attck_techniques.
async fn technique_counts(state: &AppState) -> anyhow::Result<HashMap<String, u64>> {
    let body = json!({
        "size": 0,
        // #2145: conpot healthchecks arrive tagged T0886, so unfiltered
        // the fleet's own probes would count as technique usage in both
        // the kill-chain grid and the sankey flows.
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": WINDOW}}}],
            "must_not": [crate::es::internal_probe_exclusion()]
        }},
        "aggs": {
            "techs": {"terms": {"field": "honeypot.canonical_attck_techniques", "size": 40}}
        }
    });
    let result = state.es.search_agg(body).await?;
    let aggs = &result["aggregations"];
    let mut counts: HashMap<String, u64> = HashMap::new();
    for bucket in aggs["techs"]["buckets"].as_array().into_iter().flatten() {
        counts.insert(
            bucket["key"].as_str().unwrap_or("").to_string(),
            bucket["doc_count"].as_u64().unwrap_or(0),
        );
    }
    Ok(counts)
}

// --- ATT&CK coverage grid (Go: attckGrid) ---

#[derive(Serialize)]
pub struct AttckCell {
    pub tactic_idx: usize,
    pub technique_idx: usize,
    pub count: u64,
}

#[derive(Serialize)]
pub struct AttckGrid {
    pub tactics: Vec<&'static str>,
    pub techniques: Vec<String>,
    pub cells: Vec<AttckCell>,
}

/// #2046: per-technique counts folded from the rollup's hourly `tech`
/// docs. None while #2046's shared presence probe says the 48h window
/// isn't covered yet.
async fn coverage_counts(state: &AppState) -> Option<HashMap<String, u64>> {
    if !crate::rollups::window_covered(state, 48).await {
        return None;
    }
    let docs = crate::rollups::attack_hours(state, 48).await.ok()?;
    let mut counts: HashMap<String, u64> = HashMap::new();
    for doc in &docs {
        if doc["kind"].as_str().unwrap_or("") != "tech" {
            continue;
        }
        let technique = doc["technique"].as_str().unwrap_or("");
        if technique.is_empty() {
            continue;
        }
        *counts.entry(technique.to_string()).or_insert(0) += doc["count"].as_u64().unwrap_or(0);
    }
    Some(counts)
}

#[utoipa::path(
    get,
    path = "/api/v1/charts/attck-coverage",
    summary = "ATT&CK technique coverage as a grid.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn attck_coverage(State(state): State<AppState>) -> Result<Json<AttckGrid>, (StatusCode, String)> {
    // #2046: summed tech docs are the primary path; the plain terms
    // aggregation below remains the fall-through while coverage is missing.
    // The rows pipeline after this branch is byte-identical either way.
    let counts = match coverage_counts(&state).await {
        Some(counts) => counts,
        None => technique_counts(&state).await.map_err(bad_gateway)?,
    };
    let mut rows: Vec<(String, u64, usize)> = counts
        .into_iter()
        .filter_map(|(id, count)| tactic_for(&id).map(|tactic| (id, count, tactic_index(tactic))))
        .collect();
    rows.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));
    let mut grid = AttckGrid { tactics: TACTICS.to_vec(), techniques: Vec::new(), cells: Vec::new() };
    for (id, count, tactic_idx) in rows {
        grid.techniques.push(format!("{} {}", id, technique_name(&id)));
        grid.cells.push(AttckCell { tactic_idx, technique_idx: grid.techniques.len() - 1, count });
    }
    Ok(Json(grid))
}

// --- Kill-chain sankey (Go: sankeyData) ---

#[derive(Serialize)]
pub struct SankeyNode {
    pub name: String,
}

#[derive(Serialize)]
pub struct SankeyLink {
    pub source: String,
    pub target: String,
    pub value: u64,
}

#[derive(Serialize)]
pub struct SankeyData {
    pub nodes: Vec<SankeyNode>,
    pub links: Vec<SankeyLink>,
}

/// #2046: the sankey rebuilt from the rollup's hourly `link`/`touch` docs.
/// Summing per-hour link counts reproduces the live group-flow totals
/// except at hour boundaries, where a group (session or IP burst)
/// straddling two hours contributes once per hour instead of once — a
/// documented divergence of precomputing on an hourly grid. Touchedness
/// is "any touch doc with count > 0", matching the live path's presence
/// check.
async fn sankey_from_rollup(state: &AppState) -> Option<SankeyData> {
    let docs = crate::rollups::attack_hours(state, 48).await.ok()?;
    let mut flows: HashMap<(String, String), u64> = HashMap::new();
    let mut touched: HashMap<String, u64> = HashMap::new();
    for doc in &docs {
        match doc["kind"].as_str().unwrap_or("") {
            "link" => {
                let source = doc["source"].as_str()?;
                let target = doc["target"].as_str()?;
                *flows.entry((source.to_string(), target.to_string())).or_insert(0) +=
                    doc["count"].as_u64().unwrap_or(0);
            }
            "touch" => {
                let tactic = doc["tactic"].as_str()?;
                *touched.entry(tactic.to_string()).or_insert(0) += doc["count"].as_u64().unwrap_or(0);
            }
            _ => {}
        }
    }
    let nodes: Vec<SankeyNode> = TACTICS
        .iter()
        .filter(|tactic| touched.get(**tactic).copied().unwrap_or(0) > 0)
        .map(|tactic| SankeyNode { name: tactic.to_string() })
        .collect();
    let mut links: Vec<SankeyLink> = flows
        .into_iter()
        .map(|((source, target), value)| SankeyLink { source, target, value })
        .collect();
    links.sort_by_key(|link| (tactic_index(&link.source), tactic_index(&link.target)));
    Some(SankeyData { nodes, links })
}

#[utoipa::path(
    get,
    path = "/api/v1/charts/kill-chain-sankey",
    summary = "Kill-chain stages as a sankey.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn sankey(State(state): State<AppState>) -> Result<Json<SankeyData>, (StatusCode, String)> {
    // #2046: rolled links/touches are the primary path; the two-level
    // grouping aggregation below remains the fall-through while coverage
    // is missing. Node/link assembly is identical either way.
    if crate::rollups::window_covered(&state, 48).await {
        if let Some(data) = sankey_from_rollup(&state).await {
            return Ok(Json(data));
        }
    }
    // Per-session (or per-IP for sessionless sensors) technique sets, each
    // group flowing one unit between consecutive touched tactics — same
    // grouping fallback as buildKillChainSankey.
    let body = json!({
        "size": 0,
        // #2145: conpot healthchecks arrive tagged T0886, so unfiltered
        // the fleet's own probes would count as technique usage in both
        // the kill-chain grid and the sankey flows.
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": WINDOW}}}],
            "must_not": [crate::es::internal_probe_exclusion()]
        }},
        "aggs": {
            "sessions": {
                "terms": {"field": "honeypot.session", "size": GROUP_CAP},
                "aggs": {"techs": {"terms": {"field": "honeypot.canonical_attck_techniques", "size": 12}}}
            },
            "ips": {
                "terms": {"field": "source.ip", "size": GROUP_CAP},
                "aggs": {"techs": {"terms": {"field": "honeypot.canonical_attck_techniques", "size": 12}}}
            }
        }
    });
    let result = state.es.search_agg(body).await.map_err(bad_gateway)?;
    let aggs = &result["aggregations"];
    let mut flows: HashMap<(String, String), u64> = HashMap::new();
    let mut touched: HashMap<String, bool> = HashMap::new();
    for group_agg in ["sessions", "ips"] {
        for bucket in aggs[group_agg]["buckets"].as_array().into_iter().flatten() {
            let mut tactics: Vec<&str> = bucket["techs"]["buckets"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|tech| tactic_for(tech["key"].as_str().unwrap_or("")))
                .collect();
            tactics.sort_by_key(|tactic| tactic_index(tactic));
            tactics.dedup();
            for tactic in &tactics {
                touched.insert(tactic.to_string(), true);
            }
            for pair in tactics.windows(2) {
                *flows.entry((pair[0].to_string(), pair[1].to_string())).or_insert(0) += 1;
            }
        }
    }
    let nodes: Vec<SankeyNode> = TACTICS
        .iter()
        .filter(|tactic| touched.contains_key(**tactic))
        .map(|tactic| SankeyNode { name: tactic.to_string() })
        .collect();
    let mut links: Vec<SankeyLink> = flows
        .into_iter()
        .map(|((source, target), value)| SankeyLink { source, target, value })
        .collect();
    links.sort_by_key(|link| (tactic_index(&link.source), tactic_index(&link.target)));
    Ok(Json(SankeyData { nodes, links }))
}

// --- Campaign timeline (Go: timelineRow) ---

#[derive(Serialize)]
pub struct TimelineRow {
    pub cidr: String,
    pub start_ms: i64,
    pub end_ms: i64,
    pub score: f64,
    pub events: u64,
}

#[utoipa::path(
    get,
    path = "/api/v1/charts/campaign-timeline",
    summary = "Campaigns over time.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn campaign_timeline(
    State(state): State<AppState>,
) -> Result<Json<Vec<TimelineRow>>, (StatusCode, String)> {
    let campaigns = state
        .es
        .search_index(
            &["campaigns-v1"],
            json!({"size": 200, "sort": [{"first": {"order": "asc", "unmapped_type": "date"}}],
                   "query": {"match_all": {}}}),
        )
        .await
        .map_err(bad_gateway)?;
    let rows: Vec<TimelineRow> = campaigns["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| {
            let source = &hit["_source"];
            let start = chrono::DateTime::parse_from_rfc3339(source["first"].as_str()?).ok()?;
            let end = chrono::DateTime::parse_from_rfc3339(source["last"].as_str()?).ok()?;
            Some(TimelineRow {
                cidr: source["cidr"].as_str().unwrap_or("").to_string(),
                start_ms: start.timestamp_millis(),
                end_ms: end.timestamp_millis(),
                score: source["score"].as_f64().unwrap_or(0.0),
                events: source["events"].as_u64().unwrap_or(0),
            })
        })
        .collect();
    Ok(Json(rows))
}
