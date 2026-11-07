//! /api/v1/investigate/ip/{ip} — one source address's profile: activity
//! summary, sensors/ports/countries touched, credentials and commands
//! tried, sessions, techniques, and the newest events. The Go tier's
//! /investigate/ip page over its in-memory cache, re-derived as one
//! aggregation pass + one bounded event fetch.
//!
//! #1611 workstream E.2: portbridge-v2-* is queried a second time, by
//! `portbridge.src_ip`, for the OS guess and per-port connect counts — the
//! only ground truth for which ports an IP actually knocked on across
//! tunneled sensors, which see the tunnel peer rather than the real source.
//!
//! Since #1742 that family is also in EVENT_INDICES, so its documents reach
//! the main `source.ip` pass as well. That is not a double count: the second
//! pass produces a separate profile (OS, ports touched, first and last seen),
//! not another copy of the same totals.
//!
//! #1608 workstream M: /api/v1/investigate/cidr/{cidr} and
//! /api/v1/investigate/cluster?kind=&value= — the campaigns/clusters
//! drill-down analogues of the /investigate/ip page above, ported from
//! dashboard/investigate_routes.go + dashboard/ip_correlation.go +
//! intelligence.go's clusterCorrelation* functions (#354: "do this even for
//! attack campaigns"/"do this even for clusters"). Unlike the Go tier
//! (which recomputes cluster membership from an in-memory, log-tail-bounded
//! event cache — clusterIPs's own doc comment), this crate has no
//! equivalent snapshot to scan: cluster membership here is recomputed
//! directly from honeypot-v2-* the same way correlator.rs's own
//! fetch_cluster_aggregates built the attacker-clusters-v1 rows in the
//! first place, just re-run scoped to one kind+value instead of every
//! cluster at once.

use crate::contract;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;

use crate::{
    events::{row_from_source, EventRow},
    session::{technique_row, Technique},
    AppState,
};

const WINDOW: &str = "now-10d";

/// Records/sensors aggregation across EVENT_INDICES (via `Es::search`) plus a
/// second, separate portbridge-v2-* pass keyed on `portbridge.src_ip`.
///
/// This comment used to say portbridge could never be folded into the same
/// `source.ip` filter, because its `source.ip` was the tunnel peer. That is
/// no longer true: the ingest pipeline promotes `portbridge.src_ip` to
/// `source.ip`, and measured over 24h not one portbridge document is
/// fleet-sourced — the top sources are real scanners. The family is in
/// EVENT_INDICES as of #1742.
///
/// The dedicated pass stays regardless, because it answers a different
/// question: the OS guess and the per-port connect counts live only under
/// `portbridge.*` and have no ECS equivalent to aggregate.
const CORRELATION_LIMIT: usize = 200;

/// Bounds how many cluster-member IPs get folded into one `terms` query —
/// same tradeoff as the Go tier's own correlateIPsCap (ip_correlation.go):
/// a cluster's member set is otherwise unbounded, and an oversized query
/// clause is a real failure mode, not just a performance concern.
const MEMBER_IP_CAP: usize = 200;

#[derive(Serialize)]
pub struct Kv {
    pub key: String,
    pub count: u64,
}

#[derive(Serialize, Default)]
pub struct PortbridgeProfile {
    pub os: String,
    pub first: String,
    pub last: String,
    pub ports_touched: Vec<Kv>,
}

#[derive(Serialize)]
pub struct IpProfile {
    pub ip: String,
    pub total: u64,
    pub first: String,
    pub last: String,
    pub country: String,
    /// Deprecated (#3517): despite the name this holds the AS *organization
    /// name* (`source.as.organization_name`), not an AS number. Kept
    /// unchanged for existing consumers; use `as_organization` for the same
    /// value and `as_number` for the actual number.
    pub asn: String,
    /// #3517: the AS organization name, the same value `asn` carries.
    pub as_organization: String,
    /// #3517: the AS number (`source.as.asn`, a numeric field), absent when
    /// the address has none.
    pub as_number: Option<u64>,
    pub sensors: Vec<Kv>,
    pub ports: Vec<Kv>,
    pub protos: Vec<Kv>,
    pub credentials: Vec<Kv>,
    pub commands: Vec<Kv>,
    pub sessions: Vec<Kv>,
    /// ips.html's "techniques" partial (session.html's own, ips.html
    /// shares it) — same domain/name/evidence enrichment session.rs uses.
    pub techniques: Vec<Technique>,
    /// #1682: ips.html's "Indicators" tab leaderboards, dropped in the
    /// port along with the tabbed layout itself.
    pub payloads: Vec<Kv>,
    pub alerts: Vec<Kv>,
    pub fingerprints: Vec<Kv>,
    pub paths: Vec<Kv>,
    pub events: Vec<EventRow>,
    pub portbridge: Option<PortbridgeProfile>,
    /// #1682: the "Correlation & timeline" tab (ips.html's
    /// attacker-correlation-body) — everything ES has seen for this IP,
    /// not bounded to the in-memory-window `events` above. build_correlation
    /// already existed for the CIDR/cluster drill-downs; this reuses it
    /// with the same single-IP filter the rest of this handler already
    /// built.
    pub correlation: Correlation,
    /// #1689: ips.html's "confirmed malicious (sandbox)" badge. True when
    /// this address was both *carried* by a analysed sample and *reached* by
    /// a sandbox detonation of that same sample. See confirmed_malicious().
    pub confirmed_malicious: bool,
}

/// #1689: is this address confirmed malicious by the floss/sandbox join?
///
/// The signal is the agreement of two independent pipelines about the same
/// sample (matched by SHA-256): Ghidra's floss decoded a reference to this
/// address out of the binary, *and* a Windows/Linux sandbox detonation of
/// that sample actually connected to it. Either alone is weak — a string in
/// a binary may be dead config, and a contacted address may be unrelated
/// infrastructure — together they are the strongest statement this fleet can
/// make about an address.
///
/// Two queries, not a corpus scan. The Go original
/// (dashboard/ioc_correlation.go's confirmedMaliciousIPs) loaded *both*
/// entire corpora — every sandbox result and every Ghidra result, up to
/// 10,000 documents each — recomputed the whole cross-product, and then
/// asked whether one IP was in it, on every single profile view. Inverting
/// it costs one term query plus one lookup of the matching samples, and gets
/// slower with the number of sandbox runs that touched *this* address rather
/// than with the size of the corpus.
///
/// Deliberately advisory. docs/dashboard-manual-ip-block-design.md decision
/// 1 keeps the manual block action ungated on this — an operator's judgement
/// decides, this only informs it — so a false negative here costs nothing
/// and is far preferable to a false positive.
async fn confirmed_malicious(state: &AppState, ip: &str) -> bool {
    // Which sandbox runs actually contacted this address? sandbox.iocs is
    // written by both exporters (sandbox/export-result.py for Linux since
    // #1689, sandbox/windows/orchestrate/export_result.py for Windows).
    let runs = state
        .es
        .search_index(
            &["sandbox-analysis-v1"],
            json!({
                "size": 50,
                "query": {"term": {"sandbox.iocs.remote_ips": ip}},
                "_source": ["sandbox.sha256"],
            }),
        )
        .await;
    let Ok(runs) = runs else { return false };
    let samples: Vec<String> = runs["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| hit["_source"]["sandbox"]["sha256"].as_str().map(str::to_string))
        .collect();
    if samples.is_empty() {
        return false;
    }
    // Did floss decode this same address out of any of those samples? The
    // match is on the raw string content: floss emits whole strings, and an
    // address is typically embedded in a larger one ("http://1.2.3.4/x"), so
    // this is a substring query rather than a term query. Bounded to the
    // handful of samples the first query returned.
    let hits = state
        .es
        .search_index(
            &["ghidra-analysis-v1"],
            json!({
                "size": 0,
                "track_total_hits": true,
                "query": {"bool": {"filter": [
                    {"terms": {"sha256": samples}},
                    {"query_string": {
                        "query": format!("\"{ip}\""),
                        "fields": [
                            "ghidra.floss.decoded_strings",
                            "ghidra.floss.static_strings",
                            "ghidra.floss.stack_strings",
                            "ghidra.floss.tight_strings"
                        ],
                        "default_operator": "AND"
                    }}
                ]}}
            }),
        )
        .await;
    hits.map(|value| value["hits"]["total"]["value"].as_u64().unwrap_or(0) > 0).unwrap_or(false)
}

fn kv(result: &serde_json::Value, agg: &str) -> Vec<Kv> {
    result["aggregations"][agg]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|bucket| {
            let key = bucket["key"]
                .as_str()
                .map(String::from)
                .or_else(|| bucket["key"].as_i64().map(|n| n.to_string()))
                .or_else(|| {
                    bucket["key"].as_array().map(|parts| {
                        parts
                            .iter()
                            .map(|part| part.as_str().unwrap_or(""))
                            .collect::<Vec<_>>()
                            .join(" / ")
                    })
                })?;
            Some(Kv { key, count: bucket["doc_count"].as_u64().unwrap_or(0) })
        })
        .collect()
}

/// #3517: the AS number of the most frequent `source.as.asn` bucket, if any.
/// The field is numeric in the index, so the bucket key is a JSON number;
/// a string key is tolerated in case a mapping ever serves it as keyword.
fn as_number_from(result: &serde_json::Value) -> Option<u64> {
    let key = &result["aggregations"]["as_number"]["buckets"][0]["key"];
    key.as_u64().or_else(|| key.as_str().and_then(|text| text.trim_start_matches("AS").parse().ok()))
}

/// #3517: (organization name, AS number) for the profile's `as_organization`
/// / deprecated `asn` and `as_number` fields.
fn as_profile(result: &serde_json::Value) -> (String, Option<u64>) {
    let organization = kv(result, "asn").first().map(|row| row.key.clone()).unwrap_or_default();
    (organization, as_number_from(result))
}

/// #3518: the real number of distinct sensors behind a correlation. `cardinality`
/// is the `event.sensor` cardinality aggregation (exact below its precision
/// threshold); the portbridge pseudo-sensor is appended to the top-N list
/// separately, so it is counted here too. Never below the list actually shown.
fn sensors_total(cardinality: u64, portbridge_total: u64, listed: usize) -> u64 {
    (cardinality + u64::from(portbridge_total > 0)).max(listed as u64)
}

#[utoipa::path(
    get,
    path = "/api/v1/investigate/ip/{ip}",
    summary = "Everything one source address did, across sensors.",
    params(
        ("ip" = inline(String), Path, description = "Source address to profile. A non-address is a 400."),
    ),
    responses(
        (status = 200, description = "Success. `asn` is deprecated: it holds the AS organization name, not a number; use `as_organization` (same value) and `as_number` (the AS number, null when unknown). `correlation.sensors` is the top 10 only; `correlation.sensors_total` is the real distinct-sensor count.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Result<Json<IpProfile>, (StatusCode, String)> {
    if ip.parse::<IpAddr>().is_err() {
        return Err((StatusCode::BAD_REQUEST, "invalid ip".into()));
    }
    let filter = json!({"bool": {"filter": [
        {"term": {"source.ip": ip}},
        {"range": {"@timestamp": {"gte": WINDOW}}}
    // #2145: the IP profile page renders attacker totals; investigating a
    // fleet/self address should surface its healthchecks as probes, not
    // as attacker activity.
    ], "must_not": [crate::es::internal_probe_exclusion()]}});
    let agg_body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": filter,
        "aggs": {
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
            "country": {"terms": {"field": "source.geo.country_iso_code", "size": 1}},
            "asn": {"terms": {"field": "source.as.organization_name", "size": 1}},
            "as_number": {"terms": {"field": "source.as.asn", "size": 1}},
            "sensors": {"terms": {"field": "event.sensor", "size": 30}},
            "ports": {"terms": {"field": "destination.port", "size": 20}},
            "protos": {"terms": {"field": "network.protocol", "size": 20}},
            // #3213: the same removal as dashboard.rs's `creds`, for the
            // same reason -- a multi_terms bucket key carrying the password
            // cannot be scrubbed after Elasticsearch assembles it, so the
            // field must not be requested. Accounts only.
            "creds": {"terms": {"field": "honeypot.username", "size": 20}},
            "commands": {"terms": {"field": "honeypot.canonical_command", "size": 20}},
            "sessions": {"terms": {"field": "honeypot.session", "size": 20}},
            "techniques": {"terms": {"field": "honeypot.canonical_attck_techniques", "size": 20}},
            "payloads": {"terms": {"field": "honeypot.canonical_shasum", "size": 20}},
            "alerts": {"terms": {"field": "suricata.eve.alert.signature", "size": 20}},
            "fingerprints": {"terms": {"field": "honeypot.canonical_fingerprint", "size": 20}},
            "paths": {"terms": {"field": "honeypot.path", "size": 20}}
        }
    });
    let events_body = json!({
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": filter
    });
    let portbridge_filter = json!({"bool": {"filter": [
        {"term": {"portbridge.src_ip": ip}},
        {"range": {"@timestamp": {"gte": WINDOW}}}
    ]}});
    let portbridge_body = json!({
        "size": 0,
        "query": portbridge_filter,
        "aggs": {
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
            "os": {"terms": {"field": "portbridge.os", "size": 1}},
            "ports": {"terms": {"field": "portbridge.port", "size": 20}}
        }
    });
    let (aggs, events, portbridge) = tokio::try_join!(
        state.es.search(agg_body),
        state.es.search(events_body),
        state.es.search_index(&["portbridge-v2-*"], portbridge_body)
    )
    .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    // #1682: the "Correlation & timeline" tab — everything ES has seen for
    // this IP, unbounded by the `events` window above. Not run inside the
    // try_join! above: build_correlation does 3 of its own ES calls
    // internally and this page's own doc comment already treats this data
    // as "purely informational context", not hot-path.
    let correlation = build_correlation(&state, filter.clone(), portbridge_filter.clone())
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    let total = aggs["hits"]["total"]["value"].as_u64().unwrap_or(0);
    if total == 0 {
        return Err((StatusCode::NOT_FOUND, "no events for this ip".into()));
    }
    let text = |value: &serde_json::Value| value.as_str().unwrap_or("").to_string();
    let rows: Vec<EventRow> = events["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(crate::events::row_from_hit).collect())
        .unwrap_or_default();

    let is_confirmed = confirmed_malicious(&state, &ip).await;
    let (as_organization, as_number) = as_profile(&aggs);
    Ok(Json(IpProfile {
        confirmed_malicious: is_confirmed,
        ip,
        total,
        first: text(&aggs["aggregations"]["first"]["value_as_string"]),
        last: text(&aggs["aggregations"]["last"]["value_as_string"]),
        country: kv(&aggs, "country").first().map(|row| row.key.clone()).unwrap_or_default(),
        asn: as_organization.clone(),
        as_organization,
        as_number,
        sensors: kv(&aggs, "sensors"),
        ports: kv(&aggs, "ports"),
        protos: kv(&aggs, "protos"),
        credentials: kv(&aggs, "creds")
            .into_iter()
            .map(|mut row| {
                // Same telnet-NUL cleanup the overview cred table applies.
                row.key = row.key.replace("\\x00", "").chars().filter(|c| !c.is_control()).collect();
                row
            })
            .collect(),
        commands: kv(&aggs, "commands"),
        sessions: kv(&aggs, "sessions"),
        techniques: kv(&aggs, "techniques").into_iter().map(|row| technique_row(row.key, row.count)).collect(),
        payloads: kv(&aggs, "payloads"),
        alerts: kv(&aggs, "alerts"),
        fingerprints: kv(&aggs, "fingerprints"),
        paths: kv(&aggs, "paths"),
        events: rows,
        portbridge: {
            let os = kv(&portbridge, "os").first().map(|row| row.key.clone()).unwrap_or_default();
            let ports_touched = kv(&portbridge, "ports");
            let first = text(&portbridge["aggregations"]["first"]["value_as_string"]);
            let last = text(&portbridge["aggregations"]["last"]["value_as_string"]);
            if os.is_empty() && ports_touched.is_empty() && first.is_empty() {
                None
            } else {
                Some(PortbridgeProfile { os, first, last, ports_touched })
            }
        },
        correlation,
    }))
}

/// One p0f-tagged portbridge tunnel-connect hit, shaped like `EventRow` so
/// the frontend's correlated-records table can render honeypot/Suricata and
/// portbridge rows through the exact same columns — but built by hand
/// rather than through `row_from_source`, since portbridge-v2-* documents
/// don't share the honeypot/Suricata ECS envelope `row_from_source` expects
/// (no `event.sensor`, no `source.ip`; see this module's doc comment).
fn portbridge_row(src: &Value) -> EventRow {
    let text = |v: &Value| v.as_str().unwrap_or("").to_string();
    let os = text(&src["portbridge"]["os"]);
    let port = src["portbridge"]["port"]
        .as_u64()
        .map(|p| p.to_string())
        .unwrap_or_else(|| text(&src["portbridge"]["port"]));
    let mut detail = "tunnel connect".to_string();
    if !port.is_empty() {
        detail.push_str(&format!(" · port {port}"));
    }
    if !os.is_empty() {
        detail.push_str(&format!(" · p0f: {os}"));
    }
    let src_ip = text(&src["portbridge"]["src_ip"]);
    EventRow {
        // A portbridge document is the relay's own record, so there is no
        // second join to disagree with it.
        src_ip_claimed: String::new(),
        // Synthesised from a portbridge document rather than read from a
        // hit, so it has no id and offers no full-detail action.
        id: String::new(),
        time: text(&src["@timestamp"]),
        sensor: "portbridge".to_string(),
        // #3555: read from the same document as everything else here. A
        // portbridge doc has `source.geo.city_name` (1.4M docs) and no
        // `source.port`, so src_port stays absent for these rows in practice.
        src_port: if src_ip.is_empty() { None } else { crate::events::src_port_from_source(src) },
        src_ip,
        country: String::new(),
        city: Some(text(&src["source"]["geo"]["city_name"])).filter(|city| !city.is_empty()),
        // No rating, kind or technique is written by the relay, so none is
        // invented here.
        severity: None,
        kind: None,
        techniques: Vec::new(),
        port,
        proto: String::new(),
        detail,
        session: String::new(),
        // portbridge docs carry no honeypot.* namespace, so every pivot
        // extraction comes back empty — harmless and correct.
        pivots: crate::events::pivots_from_source(src),
        record: src.clone(),
    }
}

#[derive(Serialize)]
pub struct Correlation {
    pub total: u64,
    pub truncated: bool,
    /// The top 10 sensors by event count (plus the portbridge pseudo-sensor).
    pub sensors: Vec<Kv>,
    /// #3518: the real distinct-sensor count (`cardinality` on
    /// `event.sensor`, plus the portbridge pseudo-sensor when it has hits).
    /// Always >= `sensors.len()`.
    pub sensors_total: u64,
    pub tunnel_connections: u64,
    pub tunnel_os_guesses: Vec<String>,
    pub records: Vec<EventRow>,
}

/// Runs the honeypot/Suricata `filter` (sensors aggregation + a bounded,
/// newest-first hit fetch) alongside the portbridge `portbridge_filter`
/// pass, then merges both hit sets into one time-sorted, capped records
/// list — the unified "Correlated records" table dashboard/ui/intel.html's
/// cidr-correlation-body/cluster-correlation-body templates both render.
async fn build_correlation(state: &AppState, filter: Value, portbridge_filter: Value) -> anyhow::Result<Correlation> {
    let agg_body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": filter,
        "aggs": {
            "sensors": {"terms": {"field": "event.sensor", "size": 30}},
            "sensors_total": {"cardinality": {"field": "event.sensor"}}
        }
    });
    let events_body = json!({
        "size": CORRELATION_LIMIT,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": filter
    });
    let portbridge_body = json!({
        "size": CORRELATION_LIMIT,
        "track_total_hits": true,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": portbridge_filter,
        "aggs": {"os": {"terms": {"field": "portbridge.os", "size": 20}}}
    });
    let (aggs, events, portbridge) = tokio::try_join!(
        state.es.search(agg_body),
        state.es.search(events_body),
        state.es.search_index(&["portbridge-v2-*"], portbridge_body)
    )?;

    let main_total = aggs["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let portbridge_total = portbridge["hits"]["total"]["value"].as_u64().unwrap_or(0);

    let mut records: Vec<EventRow> = events["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(|hit| row_from_source(&hit["_source"])).collect())
        .unwrap_or_default();
    let portbridge_records: Vec<EventRow> = portbridge["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(|hit| portbridge_row(&hit["_source"])).collect())
        .unwrap_or_default();
    records.extend(portbridge_records);
    // ISO-8601 @timestamp strings sort correctly as plain strings.
    records.sort_by(|a, b| b.time.cmp(&a.time));
    records.truncate(CORRELATION_LIMIT);

    let mut sensors = kv(&aggs, "sensors");
    if portbridge_total > 0 {
        sensors.push(Kv { key: "portbridge".to_string(), count: portbridge_total });
    }
    sensors.sort_by_key(|s| std::cmp::Reverse(s.count));
    sensors.truncate(10);
    let sensors_total = sensors_total(
        aggs["aggregations"]["sensors_total"]["value"].as_u64().unwrap_or(0),
        portbridge_total,
        sensors.len(),
    );

    let mut tunnel_os_guesses: Vec<String> = kv(&portbridge, "os").into_iter().map(|row| row.key).collect();
    tunnel_os_guesses.sort();

    let total = main_total + portbridge_total;
    Ok(Correlation {
        total,
        truncated: total > records.len() as u64,
        sensors,
        sensors_total,
        tunnel_connections: portbridge_total,
        tunnel_os_guesses,
        records,
    })
}

/// Validates CIDR notation the same way Go's `net.ParseCIDR` does for this
/// route (dashboard/ip_correlation.go's cidrCorrelationShell) — advisory
/// only; the address does not need to already be the network's own masked
/// address (`net.ParseCIDR("203.0.113.42/24")` is equally valid).
fn valid_cidr(cidr: &str) -> bool {
    let Some((addr, prefix)) = cidr.split_once('/') else { return false };
    let Ok(addr) = addr.parse::<IpAddr>() else { return false };
    let Ok(prefix) = prefix.parse::<u8>() else { return false };
    match addr {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

#[derive(Serialize)]
pub struct CidrCorrelation {
    pub cidr: String,
    pub correlation: Correlation,
}

#[utoipa::path(
    get,
    path = "/api/v1/investigate/cidr/{cidr}",
    summary = "Correlation across one CIDR block.",
    params(
        ("cidr" = inline(String), Path, description = "CIDR block to correlate. A malformed block is a 400."),
    ),
    responses(
        (status = 200, description = "Success. `correlation.sensors` is the top 10 only; `correlation.sensors_total` is the real distinct-sensor count.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/investigate/cidr/{cidr} — campaigns' "ES →" drill-down:
/// everything Elasticsearch has correlated for a whole network at once,
/// via the `ip` field type's native CIDR term matching (the same query
/// shape as the single-IP filter above, one different operand — see
/// correlateCIDR's own comment in ip_correlation.go).
///
/// {cidr} carries a literal "/" (CIDR notation always has one), so the
/// frontend route must percent-encode it (`encodeURIComponent`) before
/// building the request path — axum's router splits path segments on the
/// raw, not-yet-decoded request-target, so an encoded "%2F" stays inside
/// this one `{cidr}` segment and Path<String> decodes it back to "/"
/// exactly once. Same one-decode-only property investigate_routes.go's own
/// doc comment calls out for the Go tier's `{cidr...}` wildcard.
pub async fn cidr(
    State(state): State<AppState>,
    Path(cidr): Path<String>,
) -> Result<Json<CidrCorrelation>, (StatusCode, String)> {
    if !valid_cidr(&cidr) {
        return Err((StatusCode::BAD_REQUEST, "invalid cidr".into()));
    }
    let filter = json!({"bool": {"filter": [
        {"term": {"source.ip": cidr}},
        {"range": {"@timestamp": {"gte": WINDOW}}}
    ], "must_not": [crate::es::internal_probe_exclusion()]}});
    let portbridge_filter = json!({"bool": {"filter": [
        {"term": {"portbridge.src_ip": cidr}},
        {"range": {"@timestamp": {"gte": WINDOW}}}
    ]}});
    let correlation = build_correlation(&state, filter, portbridge_filter)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(Json(CidrCorrelation { cidr, correlation }))
}

#[derive(Deserialize)]
pub struct ClusterQuery {
    pub kind: String,
    pub value: String,
}

#[derive(Serialize)]
pub struct ClusterCorrelation {
    pub kind: String,
    pub value: String,
    pub ip_count: u64,
    pub correlation: Correlation,
}

/// Maps a clusters-page kind (correlator.rs's own ClusterBucket.kind values
/// — "fingerprint"/"payload"/"asn"/"provider", the attacker-clusters-v1
/// rows /api/v1/clusters already serves) to the honeypot-v2-* field its
/// members share. "asn" is stored as `"AS{asn} {org}"` (correlator.rs's
/// to_bucket/fetch_cluster_aggregates) — the numeric ASN is re-extracted
/// from that prefix since `source.as.asn` itself is numeric.
fn cluster_membership_filter(kind: &str, value: &str) -> Option<Value> {
    match kind {
        "fingerprint" => Some(json!({"term": {"honeypot.canonical_fingerprint": value}})),
        "payload" => Some(json!({"term": {"honeypot.canonical_shasum": value}})),
        "provider" => Some(json!({"term": {"source.as.type": value}})),
        "asn" => parse_asn_value(value).map(|asn| json!({"term": {"source.as.asn": asn}})),
        _ => None,
    }
}

fn parse_asn_value(value: &str) -> Option<i64> {
    let digits: String = value.strip_prefix("AS")?.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/investigate/cluster",
    summary = "The members of one attacker cluster.",
    params(
        ("kind" = inline(Option<contract::ClusterKind>), Query, description = "Cluster kind."),
        ("value" = inline(Option<String>), Query, description = "The cluster's value, as /api/v1/clusters reports it."),
    ),
    responses(
        (status = 200, description = "Success. `correlation.sensors` is the top 10 only; `correlation.sensors_total` is the real distinct-sensor count.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/investigate/cluster?kind=&value= — clusters' "ES →"
/// drill-down: everything Elasticsearch has correlated for a cluster's
/// member IPs. Two ES round trips: first recomputes the member IP set for
/// this kind+value (mirroring correlator.rs's own fetch_cluster_aggregates,
/// scoped to one bucket instead of all 250), then runs the same
/// build_correlation pass the CIDR handler uses, scoped by a `terms` filter
/// over that member set instead of one CIDR range.
///
/// Separate query parameters (not a packed path segment) for the same
/// reason investigate_routes.go's own #1312 doc comment gives: kind/value
/// can contain spaces ("Autonomous system") that a single escaped path
/// segment and a single escaped query string don't decode identically.
pub async fn cluster(
    State(state): State<AppState>,
    Query(q): Query<ClusterQuery>,
) -> Result<Json<ClusterCorrelation>, (StatusCode, String)> {
    let Some(membership) = cluster_membership_filter(&q.kind, &q.value) else {
        return Err((StatusCode::BAD_REQUEST, "unknown cluster kind".into()));
    };
    let member_body = json!({
        "size": 0,
        "query": {"bool": {"filter": [
            membership,
            {"exists": {"field": "source.ip"}},
            {"range": {"@timestamp": {"gte": WINDOW}}}
        // #2145: mirrors correlator.rs's cluster aggregation, which now
        // excludes probes -- this member recomputation must agree with it.
        ], "must_not": [crate::es::internal_probe_exclusion()]}},
        "aggs": {
            "ip_count": {"cardinality": {"field": "source.ip"}},
            "member_ips": {"terms": {"field": "source.ip", "size": MEMBER_IP_CAP}}
        }
    });
    let member_result = state
        .es
        .search_index(&["honeypot-v2-*"], member_body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let ip_count = member_result["aggregations"]["ip_count"]["value"].as_u64().unwrap_or(0);
    let member_ips: Vec<String> = member_result["aggregations"]["member_ips"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|bucket| bucket["key"].as_str().map(String::from))
        .collect();
    if ip_count < 2 || member_ips.is_empty() {
        return Err((StatusCode::NOT_FOUND, "cluster not found".into()));
    }

    let filter = json!({"bool": {"filter": [
        {"terms": {"source.ip": member_ips}},
        {"range": {"@timestamp": {"gte": WINDOW}}}
    ], "must_not": [crate::es::internal_probe_exclusion()]}});
    let portbridge_filter = json!({"bool": {"filter": [
        {"terms": {"portbridge.src_ip": member_ips}},
        {"range": {"@timestamp": {"gte": WINDOW}}}
    ]}});
    let correlation = build_correlation(&state, filter, portbridge_filter)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    Ok(Json(ClusterCorrelation { kind: q.kind, value: q.value, ip_count, correlation }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_cidr_accepts_v4_and_v6_rejects_garbage() {
        assert!(valid_cidr("203.0.113.0/24"));
        assert!(valid_cidr("203.0.113.42/24")); // unmasked address is fine, same as net.ParseCIDR
        assert!(valid_cidr("2001:db8::/32"));
        assert!(!valid_cidr("203.0.113.0"));
        assert!(!valid_cidr("203.0.113.0/33"));
        assert!(!valid_cidr("not-an-ip/24"));
        assert!(!valid_cidr("2001:db8::/129"));
    }

    #[test]
    fn parse_asn_value_extracts_leading_number() {
        assert_eq!(parse_asn_value("AS15169 Google LLC"), Some(15169));
        assert_eq!(parse_asn_value("AS64512"), Some(64512));
        assert_eq!(parse_asn_value("Google LLC"), None);
        assert_eq!(parse_asn_value("AS"), None);
    }

    #[test]
    fn cluster_membership_filter_maps_known_kinds_and_rejects_unknown() {
        assert!(cluster_membership_filter("fingerprint", "abc").is_some());
        assert!(cluster_membership_filter("payload", "deadbeef").is_some());
        assert!(cluster_membership_filter("provider", "hosting").is_some());
        assert_eq!(
            cluster_membership_filter("asn", "AS15169 Google"),
            Some(json!({"term": {"source.as.asn": 15169}}))
        );
        assert!(cluster_membership_filter("asn", "not-an-asn").is_none());
        assert!(cluster_membership_filter("bogus-kind", "x").is_none());
    }

    #[test]
    fn as_number_reads_the_numeric_source_as_asn_bucket() {
        let aggs = json!({"aggregations": {"as_number": {"buckets": [{"key": 15169, "doc_count": 4}]}}});
        assert_eq!(as_number_from(&aggs), Some(15169));
        let keyword = json!({"aggregations": {"as_number": {"buckets": [{"key": "AS64512", "doc_count": 1}]}}});
        assert_eq!(as_number_from(&keyword), Some(64512));
        let none = json!({"aggregations": {"as_number": {"buckets": []}}});
        assert_eq!(as_number_from(&none), None);
        assert_eq!(as_number_from(&json!({})), None);
    }

    #[test]
    fn as_profile_pairs_the_organization_with_the_number() {
        let aggs = json!({"aggregations": {
            "asn": {"buckets": [{"key": "Example Hosting", "doc_count": 2}]},
            "as_number": {"buckets": [{"key": 64512, "doc_count": 2}]}
        }});
        assert_eq!(as_profile(&aggs), ("Example Hosting".to_string(), Some(64512)));
        assert_eq!(as_profile(&json!({})), (String::new(), None));
    }

    #[test]
    fn ip_profile_aggregates_the_as_number_from_source_as_asn() {
        // The profile's aggregation body is built inline in `ip`; guard the
        // field names the parsers above depend on.
        let src = include_str!("investigate.rs");
        assert!(src.contains(r#""as_number": {"terms": {"field": "source.as.asn", "size": 1}}"#));
        assert!(src.contains(r#""asn": {"terms": {"field": "source.as.organization_name", "size": 1}}"#));
    }

    #[test]
    fn sensors_total_counts_portbridge_and_never_undercuts_the_list() {
        assert_eq!(sensors_total(34, 0, 10), 34);
        assert_eq!(sensors_total(34, 5, 10), 35);
        // A zero/failed cardinality still reports at least what is listed.
        assert_eq!(sensors_total(0, 7, 3), 3);
        assert_eq!(sensors_total(2, 0, 2), 2);
    }

    #[test]
    fn correlation_serializes_sensors_total_beside_the_capped_list() {
        let correlation = Correlation {
            total: 0,
            truncated: false,
            sensors: vec![Kv { key: "a".into(), count: 1 }],
            sensors_total: 34,
            tunnel_connections: 0,
            tunnel_os_guesses: Vec::new(),
            records: Vec::new(),
        };
        let wire = serde_json::to_value(&correlation).unwrap();
        assert_eq!(wire["sensors_total"], 34);
        assert_eq!(wire["sensors"].as_array().unwrap().len(), 1);
    }
}
