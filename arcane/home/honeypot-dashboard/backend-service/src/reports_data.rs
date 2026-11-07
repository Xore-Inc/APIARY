//! Report telemetry dataset, ported from report_pdf.go's reportDataFor —
//! Go filters an in-memory, already-loaded event slice (s.getEvents());
//! this crate has no such cache (every read endpoint queries Elasticsearch
//! directly, see events.rs/aggregates.rs/dashboard.rs), so the same
//! summary/top-N/findings dataset is rebuilt as ES aggregations instead of
//! in-memory map-counting. Field names match the ones already established
//! by those modules (source.ip, event.sensor, destination.port,
//! source.geo.country_iso_code, source.as.asn/organization_name,
//! suricata.eve.alert.signature.keyword, honeypot.event).

use serde::Serialize;
use serde_json::{json, Value};

use crate::report_pdf::{AlertRecord, Kv, ReportData, ReportEventRow, ReportSummary};
use crate::reports_store::{report_window_duration, ReportScope};
use crate::es::logins_filter;
use crate::AppState;

fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn key_string(bucket: &Value) -> String {
    let key = &bucket["key"];
    key.as_str().map(String::from).unwrap_or_else(|| {
        key.as_i64()
            .map(|n| n.to_string())
            .or_else(|| key.as_f64().map(|n| n.to_string()))
            .unwrap_or_default()
    })
}

/// One human-readable filter description per set scope field, in the same
/// order report_pdf.go's filter.describe() lists them — used for the cover
/// page's "REPORT SCOPE" line and the parameters section's "Applied
/// filters".
fn describe_filters(scope: &ReportScope) -> Vec<String> {
    let mut out = Vec::new();
    if !scope.ip.is_empty() {
        out.push(format!("source IP = {}", scope.ip));
    }
    if !scope.network.is_empty() {
        out.push(format!("network = {}", scope.network));
    }
    if !scope.sensor.is_empty() {
        out.push(format!("sensor = {}", scope.sensor));
    }
    if !scope.port.is_empty() {
        out.push(format!("port = {}", scope.port));
    }
    if !scope.signature.is_empty() {
        out.push(format!("signature = {}", scope.signature));
    }
    if !scope.country.is_empty() {
        out.push(format!("country = {}", scope.country));
    }
    if !scope.asn.is_empty() {
        out.push(format!("ASN = {}", scope.asn));
    }
    if !scope.text.is_empty() {
        out.push(format!("text = {}", scope.text));
    }
    if !scope.kind.is_empty() {
        out.push(format!("type = {}", scope.kind));
    }
    if !scope.session.is_empty() {
        out.push(format!("session = {}", scope.session));
    }
    if !scope.window.is_empty() {
        out.push(format!("window = {}", scope.window));
    }
    out
}

/// The window a scope reports on. An empty or unrecognised window is the
/// generous 30d fallback described in `scope_clauses`.
fn scope_window(scope: &ReportScope) -> (String, chrono::Duration) {
    match report_window_duration(&scope.window) {
        Some(duration) if !scope.window.is_empty() => (scope.window.clone(), duration),
        _ => ("30d".to_string(), chrono::Duration::days(30)),
    }
}

/// The period a scope covers, `now` being the generation instant.
pub fn scope_period(
    scope: &ReportScope,
    now: chrono::DateTime<chrono::Utc>,
) -> (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) {
    (now - scope_window(scope).1, now)
}

/// One ES filter clause per set scope field, each tagged with the scope
/// field it comes from, window first. The report and its preview both build
/// their query from this list, and the preview walks it cumulatively to name
/// the first field that leaves nothing to report.
fn scope_clauses(scope: &ReportScope) -> Vec<(&'static str, Value)> {
    let mut clauses: Vec<(&'static str, Value)> = Vec::new();
    // No window restriction: Go's "full observation window" is bounded by
    // whatever the in-memory cache happened to retain; there's no equivalent
    // unbounded query here, so default to a generous 30d rather than scanning
    // every document ever indexed.
    let since = format!("now-{}", scope_window(scope).0);
    clauses.push(("window", json!({"range": {"@timestamp": {"gte": since}}})));
    if !scope.ip.is_empty() {
        clauses.push(("ip", json!({"term": {"source.ip": scope.ip}})));
    }
    if !scope.network.is_empty() {
        // ES `ip`-mapped fields accept CIDR notation directly in a term query.
        clauses.push(("network", json!({"term": {"source.ip": scope.network}})));
    }
    if !scope.sensor.is_empty() {
        clauses.push(("sensor", json!({"term": {"event.sensor": scope.sensor}})));
    }
    if !scope.port.is_empty() {
        clauses.push(("port", json!({"term": {"destination.port": scope.port}})));
    }
    if !scope.signature.is_empty() {
        clauses.push((
            "signature",
            json!({"term": {"suricata.eve.alert.signature.keyword": scope.signature}}),
        ));
    }
    if !scope.country.is_empty() {
        clauses.push(("country", json!({"term": {"source.geo.country_iso_code": scope.country}})));
    }
    if !scope.asn.is_empty() {
        clauses.push(("asn", json!({"term": {"source.as.asn": scope.asn}})));
    }
    if !scope.kind.is_empty() {
        clauses.push(("type", json!({"term": {"honeypot.event": scope.kind}})));
    }
    if !scope.session.is_empty() {
        // The crate-wide session vocabulary, shared with events.rs and the
        // session pane (#2119): this clause used to match only two of the
        // three id fields, so a report scoped to a mailoney/tanner session
        // — whose events carry honeypot.session_id — silently came back
        // with zero matching telemetry.
        clauses.push(("session", crate::events::any_of(crate::events::SESSION_FIELDS, &scope.session)));
    }
    if !scope.text.is_empty() {
        clauses.push(("text", json!({"query_string": {"query": scope.text, "lenient": true}})));
    }
    clauses
}

/// Builds the ES bool/filter clauses for a report's scope — the same
/// fields the Event Explorer filter bar understands (events.rs/
/// aggregates.rs), plus the report-specific window.
fn scope_filters(scope: &ReportScope) -> Vec<Value> {
    scope_clauses(scope).into_iter().map(|(_, clause)| clause).collect()
}

/// Mirrors dashboard/payload_analysis.go's riskLevel — the one canonical
/// risk scale this dashboard reuses across sandbox/payload/report scoring
/// (report_pdf.go's reportDataFor calls the very same function). Any
/// divergence here would make a ported report show a different risk word
/// for the same score than the Go tier does/did. pub(crate) so
/// payload_static_analysis's deterministic-analyzer scoring reuses this
/// same canonical scale rather than a second copy of the same four bands.
pub(crate) fn risk_level(score: i64) -> &'static str {
    match score {
        s if s >= 75 => "critical",
        s if s >= 50 => "high",
        s if s >= 25 => "medium",
        _ => "low",
    }
}

/// reportAlertMatches ported: every non-empty scope needle (ip/network/
/// sensor/signature/country/asn — the only fields reportScope.filter()
/// actually populates on the shared `filter` type Go's version checks)
/// must substring-match the alert's Key+Message, case-insensitive.
fn alert_matches(key: &str, message: &str, scope: &ReportScope) -> bool {
    let blob = format!("{key} {message}").to_lowercase();
    let needles = [
        &scope.ip,
        &scope.network,
        &scope.sensor,
        &scope.signature,
        &scope.country,
        &scope.asn,
    ];
    needles
        .iter()
        .all(|needle| needle.is_empty() || blob.contains(&needle.to_lowercase()))
}

async fn operational_alerts(
    state: &AppState,
    scope: &ReportScope,
) -> anyhow::Result<(Vec<AlertRecord>, i64)> {
    let result = state
        .es
        .search_index(&["dashboard-alert-state-v1"], json!({"size": 500}))
        .await?;
    let mut open = 0i64;
    let mut alerts = Vec::new();
    for hit in result["hits"]["hits"].as_array().into_iter().flatten() {
        let source = &hit["_source"];
        let key = text(&source["Key"]);
        let message = text(&source["Message"]);
        if !alert_matches(&key, &message, scope) {
            continue;
        }
        let acknowledged = source["Acknowledged"].as_bool().unwrap_or(false);
        if !acknowledged {
            open += 1;
        }
        alerts.push(AlertRecord {
            message,
            count: source["Count"].as_i64().unwrap_or(0),
            acknowledged,
        });
    }
    Ok((alerts, open))
}

async fn event_appendix_rows(
    state: &AppState,
    filters: &[Value],
    limit: i64,
) -> anyhow::Result<Vec<ReportEventRow>> {
    if limit <= 0 {
        return Ok(Vec::new());
    }
    let body = json!({
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        // #2145: both the appendix rows and the summary aggregations are
        // attacker-facing report content; a sensor-scoped report would
        // otherwise count the sensor's own healthchecks in every section
        // (unlike events.rs's list, reports_data had no noise exclusion).
        "query": {"bool": {
            "filter": filters,
            "must_not": [crate::es::internal_probe_exclusion()]
        }}
    });
    let result = state.es.search(body).await?;
    Ok(result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| {
            let src = &hit["_source"];
            let alert = text(&src["suricata"]["eve"]["alert"]["signature"]);
            let command = text(&src["honeypot"]["canonical_command"]);
            let detail = {
                let d = text(&src["honeypot"]["event"]);
                if d.is_empty() {
                    text(&src["message"])
                } else {
                    d
                }
            };
            ReportEventRow {
                time: text(&src["@timestamp"]),
                sensor: text(&src["event"]["sensor"]),
                src_ip: text(&src["source"]["ip"]),
                port: src["destination"]["port"]
                    .as_u64()
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
                alert,
                detail,
                command,
                path: text(&src["url"]["path"]),
            }
        })
        .collect())
}

fn findings(summary: &ReportSummary) -> Vec<String> {
    let mut out = vec![format!(
        "{} matching events from {} unique source addresses reached {} sensors.",
        summary.events, summary.unique_sources, summary.sensors
    )];
    if summary.alerts > 0 {
        out.push(format!(
            "{} IDS or honeypot alert signatures were observed; {} records carried high-severity classifications.",
            summary.alerts, summary.high_severity
        ));
    }
    if summary.logins > 0 {
        out.push(format!(
            "{} authentication attempts were recorded across the selected scope.",
            summary.logins
        ));
    }
    if summary.payloads > 0 {
        out.push(format!(
            "{} payload observations require static and isolated sandbox triage.",
            summary.payloads
        ));
    }
    if summary.commands > 0 {
        out.push(format!(
            "{} command-execution records provide behavioral evidence.",
            summary.commands
        ));
    }
    if summary.open_operational > 0 {
        out.push(format!(
            "{} operational dashboard alerts remain open or unacknowledged.",
            summary.open_operational
        ));
    }
    if summary.events == 0 {
        out.push(
            "No telemetry matched the selected report filters in the queried window.".to_string(),
        );
    }
    out
}

fn recommendations(summary: &ReportSummary) -> Vec<String> {
    let mut out = Vec::new();
    if summary.high_severity > 0 || summary.alerts > 20 {
        out.push("Prioritize the highest-volume signatures and pivot to EveBox and Arkime for packet and session confirmation.".to_string());
    }
    if summary.payloads > 0 {
        out.push("Complete static analysis and disposable-VM sandbox runs for every unique payload hash before handling samples elsewhere.".to_string());
    }
    if summary.logins > 0 {
        out.push("Review repeated credentials, source reuse, and cross-sensor authentication patterns for campaign correlation.".to_string());
    }
    if summary.unique_sources > 0 {
        out.push("Use ASN, provider, country, fingerprint, and network pivots before considering network-level blocking.".to_string());
    }
    if summary.open_operational > 0 {
        out.push("Resolve collection or correlation problems represented by open operational alerts, then acknowledge them with an audit note.".to_string());
    }
    out.push("Treat all attribution and GeoIP results as contextual leads, not proof of actor identity or physical location.".to_string());
    out
}

/// Ports reportDataFor: builds the full telemetry dataset for a scope, via
/// two round trips (one packed aggregation request for every summary count
/// and top-N ranking, one bounded query for the event appendix rows) plus
/// one small query against the alert-state index.
pub async fn report_data_for(
    state: &AppState,
    scope: &ReportScope,
    title: String,
    appendix_limit: i64,
) -> anyhow::Result<ReportData> {
    let filters = scope_filters(scope);
    let filter_descriptions = describe_filters(scope);

    let agg_body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": {"bool": {
            "filter": filters,
            "must_not": [crate::es::internal_probe_exclusion()]
        }},
        "aggs": {
            "sensors": {"terms": {"field": "event.sensor", "size": 10, "order": [{"_count": "desc"}, {"_key": "asc"}]}},
            "unique_sources": {"cardinality": {"field": "source.ip"}},
            "top_sources": {"terms": {"field": "source.ip", "size": 12, "order": [{"_count": "desc"}, {"_key": "asc"}]}},
            "top_signatures": {"terms": {"field": "suricata.eve.alert.signature.keyword", "size": 12, "order": [{"_count": "desc"}, {"_key": "asc"}]}},
            "top_asns": {
                "terms": {"field": "source.as.asn", "size": 10, "order": [{"_count": "desc"}]},
                "aggs": {"org": {"terms": {"field": "source.as.organization_name", "size": 1}}}
            },
            "top_countries": {"terms": {"field": "source.geo.country_iso_code", "size": 10, "order": [{"_count": "desc"}, {"_key": "asc"}]}},
            "top_ports": {"terms": {"field": "destination.port", "size": 10, "order": [{"_count": "desc"}]}},
            "alerts": {"filter": {"exists": {"field": "suricata.eve.alert.signature"}}},
            "high_severity": {"filter": {"bool": {"filter": [
                {"exists": {"field": "suricata.eve.alert.severity"}},
                {"range": {"suricata.eve.alert.severity": {"lte": 2}}}
            ]}}},
            "logins": {"filter": logins_filter()},
            "payloads": {"filter": {"exists": {"field": "honeypot.shasum"}}},
            "commands": {"filter": {"exists": {"field": "honeypot.canonical_command"}}},
            "sessions": {"cardinality": {"field": "honeypot.session"}},
            "first_seen": {"min": {"field": "@timestamp"}},
            "last_seen": {"max": {"field": "@timestamp"}}
        }
    });

    let (agg_result, (operational_alerts_rows, open_operational), events) = tokio::try_join!(
        async { state.es.search(agg_body).await },
        async { operational_alerts(state, scope).await },
        async { event_appendix_rows(state, &filters, appendix_limit.max(1)).await },
    )?;

    let aggs = &agg_result["aggregations"];
    let kv_rows = |agg: &str, size: usize| -> Vec<Kv> {
        aggs[agg]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
            .take(size)
            .map(|bucket| Kv {
                key: key_string(bucket),
                count: bucket["doc_count"].as_i64().unwrap_or(0),
                link: String::new(),
                title: String::new(),
            })
            .collect()
    };
    let top_asns = aggs["top_asns"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|bucket| {
            let number = key_string(bucket);
            let org = bucket["org"]["buckets"]
                .as_array()
                .and_then(|o| o.first())
                .map(key_string)
                .unwrap_or_default();
            Kv {
                key: format!("AS{number} {org}").trim_end().to_string(),
                count: bucket["doc_count"].as_i64().unwrap_or(0),
                link: String::new(),
                title: String::new(),
            }
        })
        .collect();

    let events_count = agg_result["hits"]["total"]["value"].as_i64().unwrap_or(0);
    let mut summary = ReportSummary {
        events: events_count,
        alerts: aggs["alerts"]["doc_count"].as_i64().unwrap_or(0),
        high_severity: aggs["high_severity"]["doc_count"].as_i64().unwrap_or(0),
        unique_sources: aggs["unique_sources"]["value"].as_i64().unwrap_or(0),
        logins: aggs["logins"]["doc_count"].as_i64().unwrap_or(0),
        payloads: aggs["payloads"]["doc_count"].as_i64().unwrap_or(0),
        sessions: aggs["sessions"]["value"].as_i64().unwrap_or(0),
        commands: aggs["commands"]["doc_count"].as_i64().unwrap_or(0),
        sensors: aggs["sensors"]["buckets"]
            .as_array()
            .map(|b| b.len() as i64)
            .unwrap_or(0),
        open_operational,
        first_seen: text(&aggs["first_seen"]["value_as_string"]),
        last_seen: text(&aggs["last_seen"]["value_as_string"]),
        risk_score: 0,
        risk_level: String::new(),
    };

    let mut score: i64 = 5;
    score += (summary.alerts / 5).min(30);
    score += (summary.high_severity * 5).min(25);
    score += (summary.payloads * 3).min(15);
    score += ((summary.sensors - 1).max(0) * 2).min(10);
    score += (summary.open_operational * 2).min(10);
    score += summary.commands.min(5);
    summary.risk_score = score.min(100);
    summary.risk_level = risk_level(summary.risk_score).to_string();

    let scope_description = if filter_descriptions.is_empty() {
        "All normalized telemetry in the queried window".to_string()
    } else {
        filter_descriptions.join(" AND ")
    };

    let data = ReportData {
        generated: chrono::Utc::now(),
        title,
        scope: scope_description,
        filters: filter_descriptions,
        findings: findings(&summary),
        recommendations: recommendations(&summary),
        summary,
        events,
        top_sensors: kv_rows("sensors", 10),
        top_sources: kv_rows("top_sources", 12),
        top_signatures: kv_rows("top_signatures", 12),
        top_asns,
        top_countries: kv_rows("top_countries", 10),
        top_ports: kv_rows("top_ports", 10),
        operational_alerts: operational_alerts_rows,
    };
    Ok(data)
}

// ---------------------------------------------------------------------------
// Report preview (#3524): what a definition WOULD contain, without storing a
// PDF. The dataset is `report_data_for` -- the function the renderer is fed
// by -- and the page numbers come from `report_pdf::report_layout`, which
// runs the renderer's own drawing code, so the preview cannot disagree with
// the generated document about counts or pages.
// ---------------------------------------------------------------------------

/// Rows of an element's sample.
pub const PREVIEW_SAMPLE_ROWS: usize = 5;
/// The renderer's own cap on operational-alert rows.
const OPERATIONAL_ALERT_ROWS: usize = 40;

#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct PreviewPeriod {
    /// RFC 3339 start of the window the scope covers.
    pub from: String,
    /// RFC 3339 end of the window (the instant the preview ran).
    pub to: String,
}

#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct PreviewSection {
    /// Report element id (`top_sources`, `event_appendix`, ...).
    pub id: String,
    pub label: String,
    /// Rows the section prints; 0 means the renderer skips it.
    pub rows: usize,
    /// Pages the section touches in the PDF (0 when skipped).
    pub pages: usize,
    /// Two column headings, as the document prints them.
    pub columns: [String; 2],
    /// The first rows as `[left, right]` pairs of strings.
    pub sample: Vec<[String; 2]>,
}

#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct PreviewEmptyFilter {
    /// The scope field that first leaves no events: `window`, `ip`,
    /// `network`, `sensor`, `port`, `signature`, `country`, `asn`, `type`,
    /// `session` or `text`.
    pub field: String,
    pub message: String,
}

#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct ReportPreview {
    pub period: PreviewPeriod,
    pub events: i64,
    pub sources: i64,
    pub sensors: i64,
    pub sessions: i64,
    pub sections: Vec<PreviewSection>,
    /// Total pages of the PDF the same definition would generate.
    pub pages: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empty_filter: Option<PreviewEmptyFilter>,
}

fn pair(left: impl Into<String>, right: impl Into<String>) -> [String; 2] {
    [left.into(), right.into()]
}

fn kv_pairs(rows: &[crate::report_pdf::Kv]) -> Vec<[String; 2]> {
    rows.iter()
        .map(|row| {
            let label = if row.title.is_empty() { &row.key } else { &row.title };
            pair(label.clone(), row.count.to_string())
        })
        .collect()
}

fn element_label(id: &str) -> String {
    crate::reports_store::REPORT_ELEMENT_CATALOG
        .iter()
        .find(|element| element.id == id)
        .map(|element| element.label.to_string())
        .unwrap_or_else(|| id.to_string())
}

/// The rows an element prints and their column headings, from the same
/// dataset fields `report_pdf::draw_report_elements` reads for it.
fn element_rows(id: &str, data: &ReportData, appendix_limit: i64) -> ([String; 2], Vec<[String; 2]>) {
    use crate::report_pdf::*;
    let summary = &data.summary;
    let numbered = |items: &[String]| -> Vec<[String; 2]> {
        items.iter().enumerate().map(|(i, text)| pair((i + 1).to_string(), text.clone())).collect()
    };
    match id {
        ELEMENT_COVER => (
            pair("Field", "Value"),
            vec![
                pair("Title", data.title.clone()),
                pair("Report scope", data.scope.clone()),
                pair(
                    "Observed window",
                    format!(
                        "{} to {}",
                        if summary.first_seen.is_empty() { "unknown" } else { &summary.first_seen },
                        if summary.last_seen.is_empty() { "unknown" } else { &summary.last_seen },
                    ),
                ),
            ],
        ),
        ELEMENT_METRICS => (
            pair("Metric", "Value"),
            vec![
                pair("Matching events", summary.events.to_string()),
                pair("Unique sources", summary.unique_sources.to_string()),
                pair("Alert records", summary.alerts.to_string()),
                pair("High severity", summary.high_severity.to_string()),
                pair("Login attempts", summary.logins.to_string()),
                pair("Payload observations", summary.payloads.to_string()),
                pair("Sessions", summary.sessions.to_string()),
                pair("Risk rating", format!("{} - {}", summary.risk_score, summary.risk_level.to_uppercase())),
            ],
        ),
        ELEMENT_ASSESSMENT => (
            pair("Item", "Value"),
            vec![pair(
                "Triage score",
                format!("{}/100 ({})", summary.risk_score, summary.risk_level.to_uppercase()),
            )],
        ),
        ELEMENT_FINDINGS => (pair("#", "Finding"), numbered(&data.findings)),
        ELEMENT_RECOMMENDATIONS => (pair("#", "Action"), numbered(&data.recommendations)),
        ELEMENT_TOP_SENSORS => (pair("Sensor", "Events"), kv_pairs(&data.top_sensors)),
        ELEMENT_TOP_SOURCES => (pair("Source IP", "Events"), kv_pairs(&data.top_sources)),
        ELEMENT_TOP_SIGNATURES => (pair("Signature", "Events"), kv_pairs(&data.top_signatures)),
        ELEMENT_TOP_ASNS => (pair("ASN / organization", "Events"), kv_pairs(&data.top_asns)),
        ELEMENT_TOP_COUNTRIES => (pair("Country", "Events"), kv_pairs(&data.top_countries)),
        ELEMENT_TOP_PORTS => (pair("Port", "Events"), kv_pairs(&data.top_ports)),
        ELEMENT_OPERATIONAL_ALERTS => (
            pair("State / message", "Count"),
            data.operational_alerts
                .iter()
                .take(OPERATIONAL_ALERT_ROWS)
                .map(|alert| {
                    let state = if alert.acknowledged { "ACKNOWLEDGED" } else { "OPEN" };
                    pair(format!("{state} - {}", alert.message), alert.count.to_string())
                })
                .collect(),
        ),
        ELEMENT_EVENT_APPENDIX => {
            let limit = usize::try_from(appendix_limit).unwrap_or(0).min(data.events.len());
            (
                pair("Time | sensor | source", "Detail"),
                data.events[..limit]
                    .iter()
                    .map(|event| {
                        let head = [event.time.as_str(), event.sensor.as_str(), event.src_ip.as_str(), event.port.as_str()]
                            .join(" | ");
                        let detail = [&event.alert, &event.detail, &event.command, &event.path]
                            .into_iter()
                            .find(|v| !v.is_empty())
                            .cloned()
                            .unwrap_or_else(|| "event".to_string());
                        pair(head, detail)
                    })
                    .collect(),
            )
        }
        ELEMENT_PARAMETERS => (
            pair("Item", "Value"),
            vec![
                pair(
                    "Applied filters",
                    if data.filters.is_empty() { "none - executive overview".to_string() } else { data.filters.join("; ") },
                ),
                pair("Data source", "Normalized dashboard telemetry and persistent operational alert state"),
                pair("Limitations", "GeoIP, ASN and risk scoring are triage aids, not attribution"),
            ],
        ),
        _ => (pair("", ""), Vec::new()),
    }
}

/// Assembles the preview from an assembled dataset and its laid-out pages.
/// Pure: everything it reports was already computed by the data path the
/// renderer shares.
pub fn build_preview(
    data: &ReportData,
    appendix_limit: i64,
    period: (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>),
    total_pages: usize,
    placements: &[crate::report_pdf::ElementPlacement],
) -> ReportPreview {
    let sections = placements
        .iter()
        .map(|placement| {
            let (columns, rows) = element_rows(&placement.id, data, appendix_limit);
            PreviewSection {
                label: element_label(&placement.id),
                id: placement.id.clone(),
                rows: rows.len(),
                pages: placement.pages,
                columns,
                sample: rows.into_iter().take(PREVIEW_SAMPLE_ROWS).collect(),
            }
        })
        .collect::<Vec<_>>();
    ReportPreview {
        period: PreviewPeriod { from: period.0.to_rfc3339(), to: period.1.to_rfc3339() },
        events: data.summary.events,
        sources: data.summary.unique_sources,
        sensors: data.summary.sensors,
        sessions: data.summary.sessions,
        sections,
        pages: total_pages,
        empty_filter: None,
    }
}

fn empty_filter_message(field: &str, scope: &ReportScope) -> String {
    match field {
        "window" => format!("No events in the last {}.", scope_window(scope).0),
        "ip" => format!("Source {} sent nothing in this window.", scope.ip),
        "network" => format!("Network {} sent nothing in this window.", scope.network),
        "sensor" => format!("Sensor {} recorded nothing in this window.", scope.sensor),
        "port" => format!("Nothing reached port {} in this window.", scope.port),
        "signature" => format!("No IDS alert matching \"{}\" in this window.", scope.signature),
        "country" => format!("No events from country {} in this window.", scope.country),
        "asn" => format!("No events from AS{} in this window.", scope.asn),
        "type" => format!("No {} events in this window.", scope.kind),
        "session" => format!("Session {} has no events in this window.", scope.session),
        _ => format!("Nothing matches the text filter \"{}\" in this window.", scope.text),
    }
}

/// Request body that counts events after each cumulative scope clause.
fn empty_filter_body(clauses: &[(&'static str, Value)]) -> Value {
    let steps: serde_json::Map<String, Value> = (0..clauses.len())
        .map(|i| {
            let filter: Vec<&Value> = clauses[..=i].iter().map(|(_, clause)| clause).collect();
            (i.to_string(), json!({"bool": {"filter": filter}}))
        })
        .collect();
    json!({
        "size": 0,
        "track_total_hits": false,
        "query": {"bool": {"must_not": [crate::es::internal_probe_exclusion()]}},
        "aggs": {"steps": {"filters": {"filters": steps}}}
    })
}

/// The first scope field whose cumulative clause leaves zero events.
fn first_empty_field(result: &Value, clauses: &[(&'static str, Value)]) -> Option<&'static str> {
    clauses.iter().enumerate().find_map(|(i, (field, _))| {
        let count = result["aggregations"]["steps"]["buckets"][i.to_string()]["doc_count"].as_i64()?;
        (count == 0).then_some(*field)
    })
}

async fn find_empty_filter(state: &AppState, scope: &ReportScope) -> anyhow::Result<Option<PreviewEmptyFilter>> {
    let clauses = scope_clauses(scope);
    let result = state.es.search(empty_filter_body(&clauses)).await?;
    Ok(first_empty_field(&result, &clauses).map(|field| PreviewEmptyFilter {
        field: field.to_string(),
        message: empty_filter_message(field, scope),
    }))
}

/// What the definition would generate, for the telemetry templates. Uses the
/// renderer's own title, appendix default, theme and branding.
pub async fn preview_for(
    state: &AppState,
    def: &crate::reports_store::ReportDefinition,
    title: String,
) -> anyhow::Result<ReportPreview> {
    let appendix_limit = if def.appendix_limit <= 0 { 120 } else { def.appendix_limit };
    let mut data = report_data_for(state, &def.scope, title.clone(), appendix_limit).await?;
    data.title = title;
    let now = chrono::Utc::now();
    let (pages, placements) = crate::report_pdf::report_layout(
        &data,
        crate::report_pdf::pdf_theme_named(&def.theme),
        def.branding.to_pdf_branding(),
        &def.elements,
        appendix_limit,
    );
    let mut preview = build_preview(&data, appendix_limit, scope_period(&def.scope, now), pages, &placements);
    if preview.events == 0 {
        preview.empty_filter = find_empty_filter(state, &def.scope).await?;
    }
    Ok(preview)
}

#[cfg(test)]
mod preview_tests {
    use super::*;
    use crate::report_pdf::*;

    fn data_with_rows() -> ReportData {
        ReportData {
            title: "T".into(),
            scope: "window = 7d".into(),
            filters: vec!["window = 7d".into()],
            summary: ReportSummary { events: 120, unique_sources: 3, sensors: 2, sessions: 9, risk_level: "low".into(), risk_score: 7, ..Default::default() },
            top_sources: (0..8)
                .map(|i| Kv { key: format!("198.51.100.{i}"), count: 100 - i, ..Default::default() })
                .collect(),
            findings: vec!["one".into(), "two".into()],
            ..Default::default()
        }
    }

    fn elements(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    fn preview(data: &ReportData, ids: &[&str]) -> ReportPreview {
        let els = elements(ids);
        let (pages, placements) =
            report_layout(data, pdf_theme_named("dark"), default_pdf_branding(), &els, 120);
        let now = chrono::Utc::now();
        build_preview(data, 120, scope_period(&ReportScope { window: "7d".into(), ..Default::default() }, now), pages, &placements)
    }

    #[test]
    fn an_element_with_rows_reports_rows_columns_sample_and_pages() {
        let p = preview(&data_with_rows(), &["top_sources", "findings"]);
        assert_eq!((p.events, p.sources, p.sensors, p.sessions), (120, 3, 2, 9));
        let top = &p.sections[0];
        assert_eq!(top.id, "top_sources");
        assert_eq!(top.label, "Top source addresses");
        assert_eq!(top.rows, 8);
        assert_eq!(top.columns, ["Source IP".to_string(), "Events".to_string()]);
        assert_eq!(top.sample.len(), PREVIEW_SAMPLE_ROWS);
        assert_eq!(top.sample[0], ["198.51.100.0".to_string(), "100".to_string()]);
        assert!(top.pages >= 1);
        assert_eq!(p.sections[1].rows, 2);
        assert_eq!(p.sections[1].sample[1], ["2".to_string(), "two".to_string()]);
        assert!(p.pages >= 1);
        assert!(p.period.to.as_str() > p.period.from.as_str());
    }

    #[test]
    fn an_empty_scope_prints_nothing_for_table_elements() {
        let p = preview(&ReportData::default(), &["top_sources", "operational_alerts", "event_appendix"]);
        assert_eq!(p.events, 0);
        assert_eq!(p.sections[0].rows, 0);
        assert_eq!(p.sections[0].pages, 0);
        assert_eq!(p.sections[1].pages, 0);
        // The appendix still prints its "no records" paragraph.
        assert_eq!(p.sections[2].rows, 0);
        assert_eq!(p.sections[2].pages, 1);
        assert_eq!(p.pages, 1);
    }

    #[test]
    fn the_preview_page_count_matches_the_rendered_pdf() {
        let mut data = data_with_rows();
        data.top_sources = (0..12).map(|i| Kv { key: format!("k{i}"), count: 1, ..Default::default() }).collect();
        data.events = (0..120)
            .map(|i| ReportEventRow { time: format!("t{i}"), sensor: "s".into(), src_ip: "1.1.1.1".into(), detail: "x".repeat(300), ..Default::default() })
            .collect();
        let ids = ["cover", "metrics", "top_sources", "event_appendix", "parameters"];
        let els = elements(&ids);
        let (pages, _) = report_layout(&data, pdf_theme_named("dark"), default_pdf_branding(), &els, 120);
        let pdf = render_report_pdf(&data, pdf_theme_named("dark"), default_pdf_branding(), &els, 120);
        let text = String::from_utf8_lossy(&pdf);
        // One `/Type/Page/` dictionary per page (the page tree is `/Pages`).
        let rendered = text.matches("/Type/Page/").count();
        assert!(pages > 3, "appendix should spill over pages, got {pages}");
        assert_eq!(pages, rendered);
    }

    #[test]
    fn scope_filters_are_applied_to_the_query_and_the_period() {
        let scope = ReportScope { window: "7d".into(), ip: "203.0.113.5".into(), sensor: "suricata".into(), port: "22".into(), signature: "ET SCAN".into(), ..Default::default() };
        let filters = scope_filters(&scope);
        assert!(filters.contains(&json!({"range": {"@timestamp": {"gte": "now-7d"}}})));
        assert!(filters.contains(&json!({"term": {"source.ip": "203.0.113.5"}})));
        assert!(filters.contains(&json!({"term": {"event.sensor": "suricata"}})));
        assert!(filters.contains(&json!({"term": {"destination.port": "22"}})));
        assert!(filters.contains(&json!({"term": {"suricata.eve.alert.signature.keyword": "ET SCAN"}})));
        let now = chrono::Utc::now();
        let (from, to) = scope_period(&scope, now);
        assert_eq!(to - from, chrono::Duration::days(7));
        // No window: the same 30d fallback the query uses.
        let (from, to) = scope_period(&ReportScope::default(), now);
        assert_eq!(to - from, chrono::Duration::days(30));
        assert!(scope_filters(&ReportScope::default()).contains(&json!({"range": {"@timestamp": {"gte": "now-30d"}}})));
    }

    #[test]
    fn the_first_cumulative_step_with_no_events_names_the_field() {
        let scope = ReportScope { window: "24h".into(), ip: "203.0.113.5".into(), port: "22".into(), ..Default::default() };
        let clauses = scope_clauses(&scope);
        assert_eq!(clauses.iter().map(|(f, _)| *f).collect::<Vec<_>>(), ["window", "ip", "port"]);
        let body = empty_filter_body(&clauses);
        assert_eq!(body["aggs"]["steps"]["filters"]["filters"].as_object().unwrap().len(), 3);
        let result = json!({"aggregations": {"steps": {"buckets": {"0": {"doc_count": 50}, "1": {"doc_count": 0}, "2": {"doc_count": 0}}}}});
        assert_eq!(first_empty_field(&result, &clauses), Some("ip"));
        assert!(empty_filter_message("ip", &scope).contains("203.0.113.5"));
        let populated = json!({"aggregations": {"steps": {"buckets": {"0": {"doc_count": 5}, "1": {"doc_count": 2}, "2": {"doc_count": 1}}}}});
        assert_eq!(first_empty_field(&populated, &clauses), None);
    }
}
