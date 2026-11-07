//! Store-backed endpoints reading the authoritative worker/dashboard index
//! families directly (campaigns-v1, attacker-clusters-v1, attackers-v1,
//! cowrie-ttylog-v1, dashboard-alert-state-v1,
//! dashboard-payload-inventory-v1). These carry the correlators' full
//! output — scores, explanations, acknowledge state — so the port shows
//! exactly what the Go tier shows, not an approximation.
//!
//! #1611 workstream E.10: `auth-events-worker-state`, `ml-worker-state`,
//! and the other `dashboard-*-state`/`*-worker-state` indices are each a
//! single worker's own resume cursor (last-processed offset/timestamp) —
//! operational bookkeeping with no per-event or per-operator meaning, the
//! same category as a Kafka consumer group's committed offset. They're
//! deliberately absent from the `generic` allowlist below and from every
//! other endpoint in this crate; this comment is that decision on record
//! so the census question doesn't reopen.

use crate::contract;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::AppState;

#[derive(Deserialize)]
pub struct StoreQuery {
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_size")]
    pub size: u64,
    /// Free-text Lucene query string (dead-letters' search box, elastic.go's
    /// deadLetters `q` param). Only dead-letters.tsx sends this today, but
    /// every generic-backed store list can use it — additive, ignored by
    /// callers that never set it.
    #[serde(default)]
    pub q: Option<String>,
    /// #1716: restrict the recordings list to one source address. The per-IP
    /// profile has always linked here with `?ip=`; until this it was silently
    /// ignored, because the list had no source column to filter on.
    #[serde(default)]
    pub ip: Option<String>,
    /// #2179: set to "sources" on /api/v1/payloads to append a whole-store
    /// per-source census (`source_buckets` + `source_other`) to the page.
    /// Other routes ignore this; the payloads handler is the only consumer,
    /// matching how `q`/`ip` grew here before it.
    #[serde(default)]
    pub aggs: Option<String>,
}

/// Terms-agg bucket count for payloads' source census. Larger than any
/// realistic distinct-source population (dionaea/cowrie/scripts plus
/// per-directory labels), with `source_other` disclosed on top (#2179).
const SOURCES_AGG_TERMS: usize = 50;

fn default_size() -> u64 {
    25
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

/// The sort every store list is paged by: the store's own field, then a
/// deterministic tiebreak.
///
/// Both keys are load-bearing.
///
/// `unmapped_type` keeps a store whose index does not exist yet from
/// erroring -- but it also means a *misspelled* field sorts every document
/// as null instead of failing. That is how three lists shipped in no order
/// at all: ml-anomalies asked for "timestamp" where the worker writes
/// "@timestamp", auth-events asked for "last_seen" where Keycloak writes
/// "@timestamp", and static-analysis asked for "Analysis.GeneratedUTC",
/// which its documents do not carry in any spelling. It has to match the
/// field's real type, or a keyword sort reintroduces the same silent no-op.
///
/// The tiebreak is what makes paging correct rather than merely tidy.
/// `from`/`size` over a sort with ties leaves the order within a tie
/// undefined, so the same document can come back on two pages while another
/// is never shown at all -- and an all-null sort is one giant tie. `_doc` is
/// the cheapest total order Elasticsearch offers.
fn sort_spec(sort_field: &str, unmapped_type: &str) -> Value {
    json!([
        {sort_field: {"order": "desc", "unmapped_type": unmapped_type}},
        {"_doc": {"order": "asc"}}
    ])
}

/// Generic hits page: {"total": N, "rows": [ _source... ]}. The BFF/routes
/// know each store's shape; this tier guarantees ordering + paging.
async fn store_page(
    state: &AppState,
    indices: &[&str],
    sort_field: &str,
    unmapped_type: &str,
    q: &StoreQuery,
    extra_filter: Option<Value>,
) -> anyhow::Result<Value> {
    store_page_excluding(state, indices, sort_field, unmapped_type, q, extra_filter, &[]).await
}

/// The request body every store list search sends: paging, sort, query and
/// -- when a store config lists any -- the `_source.excludes` that keep
/// credential-shaped fields like canarytokens' `auth_token` out of the
/// response entirely. Elasticsearch drops excluded fields before `_source`
/// is built, so nothing downstream of this request can leak what never
/// arrived. Split out from `store_page_excluding` so the wiring itself is
/// unit-testable without a live cluster.
fn store_search_body(
    sort_field: &str,
    unmapped_type: &str,
    q: &StoreQuery,
    extra_filter: Option<Value>,
    excludes: &[&str],
) -> Value {
    let query = match extra_filter {
        Some(filter) => filter,
        None => match q.q.as_deref().map(str::trim).filter(|text| !text.is_empty()) {
            Some(text) => json!({"query_string": {"query": text, "default_operator": "AND"}}),
            None => json!({"match_all": {}}),
        },
    };
    let mut body = json!({
        "from": q.offset,
        "size": q.size.min(100),
        "track_total_hits": true,
        "sort": sort_spec(sort_field, unmapped_type),
        "query": query
    });
    if !excludes.is_empty() {
        body["_source"] = json!({"excludes": excludes});
    }
    body
}

async fn store_page_excluding(
    state: &AppState,
    indices: &[&str],
    sort_field: &str,
    unmapped_type: &str,
    q: &StoreQuery,
    extra_filter: Option<Value>,
    excludes: &[&str],
) -> anyhow::Result<Value> {
    let body = store_search_body(sort_field, unmapped_type, q, extra_filter, excludes);
    let result = state.es.search_index(indices, body).await?;
    let total = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let rows: Vec<Value> = result["hits"]["hits"]
        .as_array()
        .map(|hits| {
            hits.iter()
                .map(|hit| {
                    // _doc_id rides along for row-level actions (e.g. the
                    // ML anomaly ack keys on the anomalies page).
                    let mut row = hit["_source"].clone();
                    row["_doc_id"] = hit["_id"].clone();
                    row
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({"total": total, "rows": rows}))
}

#[utoipa::path(
    get,
    path = "/api/v1/campaigns",
    summary = "Campaign store.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PositiveInt>), Query, description = "Page size."),
        ("q" = inline(Option<String>), Query, description = "Free-text Lucene query string."),
        ("ip" = inline(Option<String>), Query, description = "Narrow to one source address."),
        ("aggs" = inline(Option<String>), Query, description = "`sources` adds the payload-inventory source buckets; anything else is ignored."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn campaigns(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    store_page(&state, &["campaigns-v1"], "score", "long", &q, None)
        .await
        .map(Json)
        .map_err(bad_gateway)
}

#[utoipa::path(
    get,
    path = "/api/v1/clusters",
    summary = "Attacker-cluster store.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PositiveInt>), Query, description = "Page size."),
        ("q" = inline(Option<String>), Query, description = "Free-text Lucene query string."),
        ("ip" = inline(Option<String>), Query, description = "Narrow to one source address."),
        ("aggs" = inline(Option<String>), Query, description = "`sources` adds the payload-inventory source buckets; anything else is ignored."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn clusters(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    store_page(&state, &["attacker-clusters-v1"], "events", "long", &q, None)
        .await
        .map(Json)
        .map_err(bad_gateway)
}

#[utoipa::path(
    get,
    path = "/api/v1/attackers",
    summary = "Attacker-entity store.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PositiveInt>), Query, description = "Page size."),
        ("q" = inline(Option<String>), Query, description = "Free-text Lucene query string."),
        ("ip" = inline(Option<String>), Query, description = "Narrow to one source address."),
        ("aggs" = inline(Option<String>), Query, description = "`sources` adds the payload-inventory source buckets; anything else is ignored."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn attackers(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    store_page(&state, &["attackers-v1"], "events", "long", &q, None)
        .await
        .map(Json)
        .map_err(bad_gateway)
}

/// GET /api/v1/recordings — one row per *recorded session*.
///
/// #1716: this used to page over `cowrie-ttylog-v1`, which is content-
/// addressed: the document `_id` is the sha256 of the recording's bytes. Bot
/// traffic is repetitive enough that identical sessions collapse onto one
/// document — 111,845 distinct sessions across 171 distinct recordings when
/// measured, one of which was produced by 28,479 sessions from 8 different
/// source IPs. Attribution columns on that list could only ever show one
/// arbitrarily-chosen session's address as though it were the answer.
///
/// The Go dashboard never had this problem because recordings.html listed one
/// row per `cowrie.log.closed` **event**, so every row genuinely had one
/// session and one address. Same-looking table, different unit. This restores
/// that unit.
///
/// Everything the list renders is native to the close event — `shasum`,
/// `size`, `duration_ms`, `session` — so there is no join and no per-row
/// lookup. The replay pane still keys on `shasum` against `cowrie-ttylog-v1`,
/// which remains the right place for the bytes: many sessions, one recording.
#[utoipa::path(
    get,
    path = "/api/v1/recordings",
    summary = "TTY recording store.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PositiveInt>), Query, description = "Page size."),
        ("q" = inline(Option<String>), Query, description = "Free-text Lucene query string."),
        ("ip" = inline(Option<String>), Query, description = "Narrow to one source address."),
        ("aggs" = inline(Option<String>), Query, description = "`sources` adds the payload-inventory source buckets; anything else is ignored."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn recordings(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let size = q.size.min(100);
    let mut filter = vec![json!({"term": {"honeypot.eventid": "cowrie.log.closed"}})];
    if let Some(ip) = q.ip.as_deref().filter(|value| !value.is_empty()) {
        filter.push(json!({"term": {"source.ip": ip}}));
    }
    let body = json!({
        "from": q.offset,
        "size": size,
        "track_total_hits": true,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": [
            "@timestamp", "source.ip", "source.geo.country_iso_code",
            "honeypot.session", "honeypot.shasum", "honeypot.size", "honeypot.duration_ms"
        ],
        // #2145: a healthcheck session against cowrie closes like a real
        // one and would render as a recordings row with empty shasum and
        // country; attacker-facing list, so probes stay out.
        "query": {"bool": {
            "filter": filter,
            "must_not": [crate::es::internal_probe_exclusion()]
        }}
    });
    let result = state
        .es
        .search_index(&["honeypot-v2-*"], body)
        .await
        .map_err(bad_gateway)?;
    let total = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let rows: Vec<Value> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| {
            let source = &hit["_source"];
            let honeypot = &source["honeypot"];
            // The tunnel endpoint appears here on 18% of close events, where
            // enrichment did not rewrite the address (#1714). Rendering it as
            // the attacker invites an operator to investigate our own
            // infrastructure, so it is reported as no attribution at all.
            // A relay address means enrichment did not recover the client;
            // do not present the relay as the attacker (#1714).
            let raw_ip = source["source"]["ip"].as_str().unwrap_or("");
            let src_ip = if raw_ip.is_empty() || raw_ip == crate::fleet::tunnel_peer_ip() {
                ""
            } else {
                raw_ip
            };
            json!({
                "when": source["@timestamp"].as_str().unwrap_or(""),
                "src_ip": src_ip,
                // ISO alpha-2, matching every other country badge in the
                // dashboard: the badge shows the code, lib/country.ts resolves
                // the full name into its tooltip (#1718).
                "country": source["source"]["geo"]["country_iso_code"].as_str().unwrap_or(""),
                "session": honeypot["session"].as_str().unwrap_or(""),
                "shasum": honeypot["shasum"].as_str().unwrap_or(""),
                "size_bytes": honeypot["size"].as_u64().unwrap_or(0),
                "duration_ms": honeypot["duration_ms"].as_u64().unwrap_or(0),
            })
        })
        .collect();
    Ok(Json(json!({"total": total, "rows": rows})))
}

#[utoipa::path(
    get,
    path = "/api/v1/alerts",
    summary = "Alert-state store.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PositiveInt>), Query, description = "Page size."),
        ("q" = inline(Option<String>), Query, description = "Free-text Lucene query string."),
        ("ip" = inline(Option<String>), Query, description = "Narrow to one source address."),
        ("aggs" = inline(Option<String>), Query, description = "`sources` adds the payload-inventory source buckets; anything else is ignored."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn alerts(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    store_page(&state, &["dashboard-alert-state-v1"], "LastSeen", "date", &q, None)
        .await
        .map(Json)
        .map_err(bad_gateway)
}

#[utoipa::path(
    get,
    path = "/api/v1/payloads",
    summary = "Captured-payload store.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PositiveInt>), Query, description = "Page size."),
        ("q" = inline(Option<String>), Query, description = "Free-text Lucene query string."),
        ("ip" = inline(Option<String>), Query, description = "Narrow to one source address."),
        ("aggs" = inline(Option<String>), Query, description = "`sources` adds the payload-inventory source buckets; anything else is ignored."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn payloads(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let mut page = store_page(&state, &["dashboard-payload-inventory-v1"], "MtimeUTC", "date", &q, None)
        .await
        .map_err(bad_gateway)?;
    // #2179: opt-in whole-store source census (`?aggs=sources`) behind one
    // terms aggregation. The filter chips used to discover sources from the
    // first loaded page only -- a source that appeared nowhere in page 1 got
    // no chip at all, so rarer captures were present but unfilterable -- and
    // each chip cost its own size=1 round-trip. The agg returns every
    // Sources value on record with its exact count; `source_other` carries
    // sum_other_doc_count so the UI can still say "+N more" if the terms
    // size itself ever becomes the bound.
    if q.aggs.as_deref() == Some("sources") {
        let result = state
            .es
            .search_index(
                &["dashboard-payload-inventory-v1"],
                json!({
                    "size": 0,
                    "aggs": {"sources": {"terms": {"field": "Sources", "size": SOURCES_AGG_TERMS}}}
                }),
            )
            .await
            .map_err(bad_gateway)?;
        page["source_buckets"] = result["aggregations"]["sources"]["buckets"].clone();
        page["source_other"] = result["aggregations"]["sources"]["sum_other_doc_count"].clone();
    }
    Ok(Json(page))
}

#[derive(Deserialize)]
pub struct AckBody {
    pub ack: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/alerts/{key}/ack",
    summary = "Acknowledge one alert.",
    params(
        ("key" = inline(String), Path, description = "Alert-state document key (the hashified signature triple)."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `AckBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// POST /api/v1/alerts/{key}/ack — flip one alert's Acknowledged flag
/// (dashboard-alert-state-v1 doc id == alert key), the ported
/// alertManager.acknowledge.
pub async fn acknowledge(
    State(state): State<AppState>,
    axum::extract::Path(key): axum::extract::Path<String>,
    Json(body): Json<AckBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    state
        .es
        .update_doc("dashboard-alert-state-v1", &key, json!({"Acknowledged": body.ack}))
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(Json(json!({"ok": true, "key": key, "ack": body.ack})))
}

/// (index, sort field, sort field type, sensitive/heavy fields excluded
/// from list responses). The type is not decoration -- see the sort spec in
/// store_page_excluding for what a wrong one costs.
type StoreConfig = (&'static str, &'static str, &'static str, &'static [&'static str]);

fn store_config(name: &str) -> Option<StoreConfig> {
    Some(match name {
        // #1611 workstream E.9: `error`, `details.username`, and
        // `details.redirect_uri` are already present here (no excludes) —
        // the workstream's ask is first-class *columns* for them on the
        // auth-events.tsx table, a frontend-only change; this passthrough
        // already carries every field they'd need.
        // "last_seen" is not a field these documents have -- Keycloak's
        // event stream writes @timestamp -- so this list came back in no
        // order at all until #1566.
        "auth-events" => ("auth-failure-events", "@timestamp", "date", &[] as &[&str]),
        // llm-worker output; index may not exist yet (ignore_unavailable).
        "llm-analysis" => ("llm-analysis", "@timestamp", "date", &[]),
        // Likewise "timestamp": the ml-worker writes @timestamp. Measured
        // on the live index, the first page mixed 20:58, 20:59 and 20:57
        // rows in that order (#1566).
        "ml-anomalies" => ("ml-anomalies", "@timestamp", "date", &[]),
        // Matches dashboard/agent_campaigns.go's own refreshAgentCampaigns
        // sort (`sort=@timestamp:asc`) — the campaign-verdict documents
        // this index holds have no last_seen field at all (see the
        // agent-intrusion-worker port's build_campaign_verdict, #1610).
        "agent-campaigns" => ("agent-intrusion-campaigns", "@timestamp", "date", &[]),
        // #3111: auth_token is the platform's password-equivalent
        // management credential (canarytokens.rs's dedicated list/create
        // endpoints already strip it via redact_record()) -- this generic
        // passthrough reads the same index and must match that invariant
        // instead of serving the raw _source.
        "canarytokens" => ("dashboard-canarytokens-v1", "created_at", "date", &["auth_token"]),
        "problem-reports" => ("dashboard-problem-reports-v1", "submitted_at", "date", &["dom_snapshot"]),
        "dead-letters" => ("dead-letter-honeypot", "@timestamp", "date", &[]),
        "yara" => ("yara-analysis-v1", "@timestamp", "date", &[]),
        "sandbox-runs" => ("sandbox-analysis-v1", "@timestamp", "date", &[]),
        "ghidra-runs" => ("ghidra-analysis-v1", "@timestamp", "date", &[]),
        // These documents carry only Analysis and Fingerprint -- there is
        // no GeneratedUTC, and no time field at all, so there is nothing to
        // order by chronologically. Fingerprint is the one mapped field, so
        // it is what makes paging deterministic instead of arbitrary.
        "static-analysis" => ("dashboard-static-analysis-v1", "Fingerprint", "keyword", &[]),
        // Result families that may not exist yet on a given deployment
        // (ignore_unavailable keeps them safe): revdeck, CAPE, GitHub.
        "revdeck" => ("revdeck-analysis-v1", "@timestamp", "date", &[]),
        "cape" => ("cape-analysis-v1", "@timestamp", "date", &[]),
        "github-analysis" => ("github-analysis-v1", "@timestamp", "date", &[]),
        "workbench-runs" => ("dashboard-workbench-runs-v1", "created_at", "date", &[]),
        "generated-reports" => ("dashboard-generated-reports-v1", "created_at", "date", &["pdf_base64"]),
        "report-definitions" => ("dashboard-reports-definitions-v1", "updated", "date", &[]),
        "intelligence" => ("dashboard-intelligence-archive-v1", "generated", "date", &[]),
        _ => return None,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/store/{name}",
    summary = "One allowlisted store, through the generic passthrough.",
    params(
        ("name" = inline(contract::StoreName), Path, description = "Allowlisted generic store. Anything else is a 404 -- this route is not an arbitrary index read."),
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PositiveInt>), Query, description = "Page size."),
        ("q" = inline(Option<String>), Query, description = "Free-text Lucene query string."),
        ("ip" = inline(Option<String>), Query, description = "Narrow to one source address."),
        ("aggs" = inline(Option<String>), Query, description = "`sources` adds the payload-inventory source buckets; anything else is ignored."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// Generic allowlisted store passthrough: /api/v1/store/{name}. Every
/// remaining store-shaped page reads through here instead of growing its
/// own handler; the allowlist keeps arbitrary index reads impossible.
pub async fn generic(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let Some((index, sort, sort_type, excludes)) = store_config(&name) else {
        return Err((StatusCode::NOT_FOUND, format!("unknown store {name}")));
    };
    store_page_excluding(&state, &[index], sort, sort_type, &q, None, excludes)
        .await
        .map(Json)
        .map_err(bad_gateway)
}

#[derive(Deserialize)]
pub struct PurgeQuery {
    #[serde(default)]
    pub q: Option<String>,
}

#[utoipa::path(
    delete,
    path = "/api/v1/store/{name}",
    summary = "Purge dead letters matching ?q= (dead-letters only).",
    params(
        ("name" = inline(contract::StoreName), Path, description = "Allowlisted generic store. Anything else is a 404 -- this route is not an arbitrary index read."),
        ("q" = inline(Option<String>), Query, description = "Lucene query string; absent or empty purges every retained dead letter."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 405, description = "The store exists but exposes no delete side (only dead-letters does).", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// DELETE /api/v1/store/{name} — allowlisted like `generic`'s GET side,
/// but only dead-letters has a delete today (ported from elastic.go's
/// purgeDeadLetters). Sharing the route with `generic` rather than
/// registering a second literal path at `/api/v1/store/dead-letters`
/// avoids relying on axum/matchit's literal-over-param route precedence
/// for what would otherwise be an overlapping registration.
///
/// Admin-gated at the BFF (not here), same posture as every other admin
/// action in this tier. Purges exactly the same `q` Lucene query-string
/// scope the GET side searches with — an absent/empty q purges every
/// retained dead letter, matching Go's documented "the operator purges
/// exactly the scope they were just looking at" contract.
pub async fn generic_delete(
    axum::extract::Path(name): axum::extract::Path<String>,
    State(state): State<AppState>,
    Query(q): Query<PurgeQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if name != "dead-letters" {
        return Err((StatusCode::METHOD_NOT_ALLOWED, format!("store {name} has no delete route")));
    }
    let query = match q.q.as_deref().map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => json!({"query_string": {"query": text, "default_operator": "AND"}}),
        None => json!({"match_all": {}}),
    };
    let deleted = state.es.delete_by_query("dead-letter-honeypot", query).await.map_err(bad_gateway)?;
    Ok(Json(json!({"deleted": deleted})))
}


#[cfg(test)]
mod sort_tests {
    use super::sort_spec;

    #[test]
    fn the_store_field_leads_and_carries_its_own_type() {
        // A date sort and a keyword sort must not both claim "date": an
        // unmapped_type that disagrees with the field is the same silent
        // no-op as a misspelled field name.
        let dated = sort_spec("@timestamp", "date");
        assert_eq!(dated[0]["@timestamp"]["order"], "desc");
        assert_eq!(dated[0]["@timestamp"]["unmapped_type"], "date");

        let keyed = sort_spec("Fingerprint", "keyword");
        assert_eq!(keyed[0]["Fingerprint"]["unmapped_type"], "keyword");
    }

    #[test]
    fn every_sort_has_a_tiebreak_so_paging_cannot_repeat_or_skip() {
        // The bug this guards. from/size over a sort with ties leaves the
        // order inside a tie undefined, so a document can appear on two
        // pages while another never appears -- and the measured live data
        // ties hard (48 ml-anomaly rows on one IP in a single second).
        for (field, kind) in [("@timestamp", "date"), ("score", "long"), ("Fingerprint", "keyword")] {
            let spec = sort_spec(field, kind);
            assert_eq!(spec.as_array().map(Vec::len), Some(2), "{field} lost its tiebreak");
            assert_eq!(spec[1]["_doc"]["order"], "asc", "{field}'s tiebreak is not a total order");
        }
    }
}

#[cfg(test)]
mod store_config_tests {
    use super::{store_config, store_search_body, StoreQuery};
    use serde_json::json;

    #[test]
    fn canarytokens_passthrough_excludes_the_management_auth_token() {
        // #3111: the dedicated canarytoken endpoints strip auth_token
        // before it ever reaches a browser -- this generic passthrough
        // reads the same index and must carry the same exclude, or the
        // credential leaks to any authenticated non-admin operator.
        let (_, _, _, excludes) = store_config("canarytokens").expect("canarytokens is a known store");
        assert!(excludes.contains(&"auth_token"), "canarytokens store must exclude auth_token");
    }

    #[test]
    fn unknown_store_name_has_no_config() {
        assert!(store_config("not-a-real-store").is_none());
    }

    #[test]
    fn canarytokens_passthrough_query_strips_auth_token_from_a_full_document() {
        // #3111: store_config listing "auth_token" is not enough on its own
        // -- generic() has to actually thread it into the request this
        // handler sends, or the config entry is decoration. This drives the
        // real store_search_body() the passthrough calls (not a
        // reimplementation of it), so a future refactor that drops the
        // wiring fails here first.
        let (_, sort_field, sort_type, excludes) =
            store_config("canarytokens").expect("canarytokens is a known store");
        let q = StoreQuery { offset: 0, size: 25, q: None, ip: None, aggs: None };
        let body = store_search_body(sort_field, sort_type, &q, None, excludes);
        assert_eq!(body["_source"]["excludes"], json!(["auth_token"]));

        // A full ES document exactly as canarytokens.rs's create() persists
        // it (see that module's es_record fixture): nine fields, credential
        // included. `_source.excludes` is a flat top-level key removal --
        // modeled here rather than requiring a live cluster -- so this
        // proves the exclude this passthrough sends actually drops
        // auth_token from a real document shape and nothing else.
        let mut full_document = json!({
            "id": "0fdec0yF",
            "token_type": "ms_word",
            "memo": "decoy 0fdec0yF",
            "token_url": "https://decoys.example-shack.net/0fdec0yF",
            "hostname": "quiet-river-4211.decoys.example-shack.net",
            "filename_hint": "quarterly-report.docx",
            "auth_token": "tok-secret-abcdef1234567890",
            "created_by": "ops",
            "created_at": "2026-08-27T00:00:00+00:00",
        });
        for field in excludes {
            full_document.as_object_mut().unwrap().remove(*field);
        }
        let wire = full_document.to_string();
        assert!(!wire.contains("auth_token"), "field name leaked past the passthrough's excludes: {wire}");
        assert!(
            !wire.contains("tok-secret-abcdef1234567890"),
            "credential value leaked past its own key: {wire}"
        );
        for kept in [
            "id", "token_type", "memo", "token_url", "hostname",
            "filename_hint", "created_by", "created_at",
        ] {
            assert!(full_document.get(kept).is_some(), "excludes dropped {kept} along with the credential");
        }
    }
}
