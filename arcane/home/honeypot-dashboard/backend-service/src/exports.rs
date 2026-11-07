//! Server-side bulk exports, ported from investigate.go's CSV exports and
//! elastic.go's history()'s attachment mode: the full filtered scope, not
//! whatever happens to be paginated into the browser (#513's own reasoning
//! in investigate.go — an export exists precisely for the rows that don't
//! fit on screen).
//!
//! Two deliberate departures from Go, both because this port already made
//! them elsewhere before this file existed and an export should match the
//! page it exports, not silently reintroduce a scope the page itself
//! doesn't show (Go's own #513 rule, applied to the port's own state):
//!   - commands.csv exports the same `events?kind=command` view
//!     commands.tsx renders (raw per-event rows), not Go's
//!     (sensor,command)-grouped aggregate with counts/first/last.
//!   - events.csv omits Go's "provider" column (a classification this tier
//!     has no confirmed source field for) — every other column present.

use crate::contract;
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
};
use serde_json::{json, Value};

use crate::events::{build_filters, row_from_source, suricata_noise_exclusion, EventsQuery};
use crate::AppState;

/// Well above anything the UI paginates (100-row store pages, 25-row list
/// pages) but still a real ES query bound — Go's own exports iterate an
/// in-memory event slice with no cap at all, which this tier has no
/// equivalent of; this is the practical stand-in.
const EXPORT_MAX_ROWS: u64 = 10_000;

/// Neutralizes a leading =, +, -, or @ (CSV/spreadsheet-formula injection:
/// a cell starting with one of those is evaluated as a formula by Excel/
/// Sheets/LibreOffice, letting attacker-controlled honeypot text execute
/// arbitrary spreadsheet formulas or DDE commands on the analyst's
/// machine). Prefixing a single quote is the standard mitigation — every
/// spreadsheet app treats a leading quote as "this is text". Ports
/// investigate.go's sanitizeCSVField exactly.
fn sanitize_csv_field(value: &str) -> String {
    match value.chars().next() {
        Some('=' | '+' | '-' | '@') => format!("'{value}"),
        _ => value.to_string(),
    }
}

fn csv_row(fields: &[String]) -> String {
    fields
        .iter()
        .map(|field| {
            let field = sanitize_csv_field(field);
            if field.contains(['"', ',', '\n', '\r']) {
                format!("\"{}\"", field.replace('"', "\"\""))
            } else {
                field
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn csv_body(header_row: &[&str], rows: &[Vec<String>]) -> String {
    let header: Vec<String> = header_row.iter().map(|value| value.to_string()).collect();
    let mut body = csv_row(&header);
    body.push_str("\r\n");
    for row in rows {
        body.push_str(&csv_row(row));
        body.push_str("\r\n");
    }
    body
}

fn csv_response(filename: &'static str, body: String) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
        ],
        body,
    )
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

fn text(value: &Value) -> String {
    value.as_str().unwrap_or("").to_string()
}

fn number(value: &Value) -> String {
    value.as_i64().map(|n| n.to_string()).unwrap_or_default()
}

fn joined(value: &Value) -> String {
    value.as_array().into_iter().flatten().filter_map(|item| item.as_str()).collect::<Vec<_>>().join(" ")
}

#[utoipa::path(
    get,
    path = "/api/v1/export/events.csv",
    summary = "The event explorer as CSV, same filters as /events.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PageSize>), Query, description = "Page size, clamped to 100 by the handler."),
        ("ip" = inline(Option<String>), Query, description = "Single source address."),
        ("ips" = inline(Option<String>), Query, description = "Comma-separated source addresses."),
        ("sensor" = inline(Option<String>), Query, description = "Sensor name (honeypot.dionaea, suricata, ...)."),
        ("country" = inline(Option<String>), Query, description = "ISO country code."),
        ("city" = inline(Option<String>), Query, description = "City name, as bucketed on the overview map."),
        ("port" = inline(Option<String>), Query, description = "Destination port."),
        ("proto" = inline(Option<String>), Query, description = "Transport protocol."),
        ("kind" = inline(Option<String>), Query, description = "honeypot.event kind (command, login, ...)."),
        ("shasum" = inline(Option<String>), Query, description = "Captured-payload hash."),
        ("community_id" = inline(Option<String>), Query, description = "One flow across every sensor that saw it."),
        ("q" = inline(Option<String>), Query, description = "Free-text query_string, passed to Elasticsearch as-is."),
        ("since" = inline(Option<String>), Query, description = "Go-style relative window (24h, 7d)."),
        ("persona" = inline(Option<String>), Query, description = "Decoy persona id."),
        ("site" = inline(Option<String>), Query, description = "Decoy site id."),
        ("asset" = inline(Option<String>), Query, description = "Decoy asset id."),
        ("fingerprint" = inline(Option<String>), Query, description = "Client fingerprint, matched across every field sensors record one in."),
        ("cmd" = inline(Option<String>), Query, description = "Exact command text."),
        ("cred" = inline(Option<String>), Query, description = "\"user / pass\" pair."),
        ("path" = inline(Option<String>), Query, description = "Request path."),
        ("session" = inline(Option<String>), Query, description = "Session id."),
        ("asn" = inline(Option<String>), Query, description = "Source AS number."),
        ("org" = inline(Option<String>), Query, description = "Source network organization."),
        ("provider" = inline(Option<String>), Query, description = "Provider class."),
        ("sig" = inline(Option<String>), Query, description = "IDS alert signature."),
        ("cat" = inline(Option<String>), Query, description = "Detection category (Suricata alert category or honeypot.category)."),
    ),
    responses(
        (status = 200, description = "CSV of the matching events.", body = inline(serde_json::Value), content_type = "text/csv"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/export/events.csv
pub async fn events_csv(
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let filters = build_filters(&q);
    let body = json!({
        "size": EXPORT_MAX_ROWS,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}}
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    let rows: Vec<Vec<String>> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| events_csv_row(&row_from_source(&hit["_source"])))
        .collect();
    Ok(csv_response("honeypot-events.csv", csv_body(EVENTS_CSV_COLUMNS, &rows)))
}

/// The `honeypot-events.csv` header.
///
/// A named list rather than an inline array so a column can be added in one
/// place, and so the width invariant below is a comparison of two named
/// things instead of a count somebody eyeballed.
const EVENTS_CSV_COLUMNS: &[&str] = &[
    "time",
    "sensor",
    "source_ip",
    "country",
    "city",
    "asn",
    "organization",
    "protocol",
    "port",
    "username",
    "password",
    "credential_status",
    "auth_outcome",
    "command",
    "path",
    "alert",
    "session",
    "payload_hash",
    "detail",
];

/// One CSV row, in `EVENTS_CSV_COLUMNS` order.
fn events_csv_row(row: &crate::events::EventRow) -> Vec<String> {
    let hp = &row.record["honeypot"];
    vec![
        row.time.clone(),
        row.sensor.clone(),
        row.src_ip.clone(),
        row.country.clone(),
        text(&row.record["source"]["geo"]["city_name"]),
        // #3704: the ingest writes `source.as.asn` / `organization_name`,
        // not the ECS `number` / `organization.name` spelling.
        number(&row.record["source"]["as"]["asn"]),
        text(&row.record["source"]["as"]["organization_name"]),
        row.proto.clone(),
        row.port.clone(),
        text(&hp["username"]),
        // #3213: `row.record` is already scrubbed by `row_from_source` (the
        // boundary runs there), so this read cannot return a secret for the
        // two decoys in scope -- including for the documents indexed before
        // the sensors were fixed. The column itself is kept: the sensors
        // outside this issue still populate it, and dropping the column would
        // be a breaking change to a download other people's tooling reads.
        text(&hp["password"]),
        // ...and the two axes that replace it, so a CSV of this decoy's events
        // still answers "was there a credential, could we read it, and was the
        // auth real" without the secret.
        text(&hp["credential_status"]),
        text(&hp["auth_outcome"]),
        text(&hp["command"]),
        text(&hp["path"]),
        text(&row.record["suricata"]["eve"]["alert"]["signature"]),
        row.session.clone(),
        text(&hp["shasum"]),
        row.detail.clone(),
    ]
}

#[utoipa::path(
    get,
    path = "/api/v1/export/commands.csv",
    summary = "Matching commands as CSV.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PageSize>), Query, description = "Page size, clamped to 100 by the handler."),
        ("ip" = inline(Option<String>), Query, description = "Single source address."),
        ("ips" = inline(Option<String>), Query, description = "Comma-separated source addresses."),
        ("sensor" = inline(Option<String>), Query, description = "Sensor name (honeypot.dionaea, suricata, ...)."),
        ("country" = inline(Option<String>), Query, description = "ISO country code."),
        ("city" = inline(Option<String>), Query, description = "City name, as bucketed on the overview map."),
        ("port" = inline(Option<String>), Query, description = "Destination port."),
        ("proto" = inline(Option<String>), Query, description = "Transport protocol."),
        ("kind" = inline(Option<String>), Query, description = "honeypot.event kind (command, login, ...)."),
        ("shasum" = inline(Option<String>), Query, description = "Captured-payload hash."),
        ("community_id" = inline(Option<String>), Query, description = "One flow across every sensor that saw it."),
        ("q" = inline(Option<String>), Query, description = "Free-text query_string, passed to Elasticsearch as-is."),
        ("since" = inline(Option<String>), Query, description = "Go-style relative window (24h, 7d)."),
        ("persona" = inline(Option<String>), Query, description = "Decoy persona id."),
        ("site" = inline(Option<String>), Query, description = "Decoy site id."),
        ("asset" = inline(Option<String>), Query, description = "Decoy asset id."),
        ("fingerprint" = inline(Option<String>), Query, description = "Client fingerprint, matched across every field sensors record one in."),
        ("cmd" = inline(Option<String>), Query, description = "Exact command text."),
        ("cred" = inline(Option<String>), Query, description = "\"user / pass\" pair."),
        ("path" = inline(Option<String>), Query, description = "Request path."),
        ("session" = inline(Option<String>), Query, description = "Session id."),
        ("asn" = inline(Option<String>), Query, description = "Source AS number."),
        ("org" = inline(Option<String>), Query, description = "Source network organization."),
        ("provider" = inline(Option<String>), Query, description = "Provider class."),
        ("sig" = inline(Option<String>), Query, description = "IDS alert signature."),
        ("cat" = inline(Option<String>), Query, description = "Detection category (Suricata alert category or honeypot.category)."),
    ),
    responses(
        (status = 200, description = "CSV of matching commands.", body = inline(serde_json::Value), content_type = "text/csv"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/export/commands.csv — see module doc: exports the same
/// `events?kind=command` scope commands.tsx itself renders.
pub async fn commands_csv(
    State(state): State<AppState>,
    Query(mut q): Query<EventsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    q.kind = Some("command".to_string());
    let filters = build_filters(&q);
    let body = json!({
        "size": EXPORT_MAX_ROWS,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}}
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    let rows: Vec<Vec<String>> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| {
            let row = row_from_source(&hit["_source"]);
            let hp = &row.record["honeypot"];
            let command = ["input", "command", "data", "message"]
                .into_iter()
                .find_map(|field| hp[field].as_str().filter(|value| !value.is_empty()))
                .map(str::to_string)
                .unwrap_or(row.detail);
            vec![row.time, row.sensor, row.src_ip, command, row.session]
        })
        .collect();
    Ok(csv_response("honeypot-commands.csv", csv_body(&["time", "sensor", "source_ip", "command", "session"], &rows)))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/ips.csv",
    summary = "Every source address in the window as CSV.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PositiveInt>), Query, description = "Page size."),
    ),
    responses(
        (status = 200, description = "CSV of source addresses.", body = inline(serde_json::Value), content_type = "text/csv"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/export/ips.csv — same aggregation aggregates::sources
/// backs /ips with, just a higher cap (that endpoint's own 1000-row cap,
/// already well above the page's 25-row pagination).
pub async fn ips_csv(State(state): State<AppState>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let page = crate::aggregates::sources(
        State(state),
        Query(crate::aggregates::PageQuery { offset: 0, size: 1000 }),
    )
    .await?
    .0;
    let rows: Vec<Vec<String>> = page
        .rows
        .iter()
        .map(|row| {
            vec![
                row.ip.clone(),
                row.country.clone(),
                row.events.to_string(),
                row.logins.to_string(),
                row.sessions.to_string(),
                row.sensors.join(" "),
                row.first.clone(),
                row.last.clone(),
            ]
        })
        .collect();
    Ok(csv_response(
        "honeypot-attack-sources.csv",
        csv_body(&["ip", "country", "events", "logins", "sessions", "sensors", "first", "last"], &rows),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/campaigns.csv",
    summary = "Campaigns as CSV.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PositiveInt>), Query, description = "Page size."),
    ),
    responses(
        (status = 200, description = "CSV of campaigns.", body = inline(serde_json::Value), content_type = "text/csv"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/export/campaigns.csv
pub async fn campaigns_csv(State(state): State<AppState>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let result = state
        .es
        .search_index(&["campaigns-v1"], json!({"size": EXPORT_MAX_ROWS, "sort": [{"score": {"order": "desc"}}]}))
        .await
        .map_err(bad_gateway)?;
    let rows: Vec<Vec<String>> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| {
            let src = &hit["_source"];
            vec![
                number(&src["score"]),
                text(&src["cidr"]),
                number(&src["events"]),
                number(&src["unique_ips"]),
                joined(&src["sensors"]),
                joined(&src["ports"]),
                number(&src["creds"]),
                number(&src["payloads"]),
                number(&src["alerts"]),
                joined(&src["providers"]),
                number(&src["fingerprints"]),
                text(&src["explanation"]),
                text(&src["first"]),
                text(&src["last"]),
            ]
        })
        .collect();
    Ok(csv_response(
        "honeypot-campaigns.csv",
        csv_body(
            &[
                "score",
                "network",
                "events",
                "unique_ips",
                "sensors",
                "ports",
                "creds",
                "payloads",
                "alerts",
                "providers",
                "fingerprints",
                "why_correlated",
                "first",
                "last",
            ],
            &rows,
        ),
    ))
}

#[derive(serde::Deserialize)]
pub struct ClustersExportQuery {
    #[serde(default)]
    kind: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/export/clusters.csv",
    summary = "Attacker clusters as CSV, by cluster kind.",
    params(
        ("kind" = inline(Option<contract::ClusterKind>), Query, description = "Cluster kind to export."),
    ),
    responses(
        (status = 200, description = "CSV of attacker clusters.", body = inline(serde_json::Value), content_type = "text/csv"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/export/clusters.csv — same ?kind= post-aggregation
/// narrowing the /clusters page itself applies client-side, applied here
/// server-side over the full result set.
pub async fn clusters_csv(
    State(state): State<AppState>,
    Query(query): Query<ClustersExportQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let kind_filter = query.kind;
    let result = state
        .es
        .search_index(&["attacker-clusters-v1"], json!({"size": EXPORT_MAX_ROWS, "sort": [{"events": {"order": "desc"}}]}))
        .await
        .map_err(bad_gateway)?;
    let rows: Vec<Vec<String>> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|hit| kind_filter.is_empty() || text(&hit["_source"]["kind"]) == kind_filter)
        .map(|hit| {
            let src = &hit["_source"];
            vec![text(&src["kind"]), text(&src["value"]), number(&src["sources"]), number(&src["events"]), joined(&src["sensors"])]
        })
        .collect();
    Ok(csv_response("honeypot-clusters.csv", csv_body(&["kind", "value", "sources", "events", "sensors"], &rows)))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/history.json",
    summary = "The behaviour-search slice as JSON.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PageSize>), Query, description = "Page size, clamped to 100 by the handler."),
        ("ip" = inline(Option<String>), Query, description = "Single source address."),
        ("ips" = inline(Option<String>), Query, description = "Comma-separated source addresses."),
        ("sensor" = inline(Option<String>), Query, description = "Sensor name (honeypot.dionaea, suricata, ...)."),
        ("country" = inline(Option<String>), Query, description = "ISO country code."),
        ("city" = inline(Option<String>), Query, description = "City name, as bucketed on the overview map."),
        ("port" = inline(Option<String>), Query, description = "Destination port."),
        ("proto" = inline(Option<String>), Query, description = "Transport protocol."),
        ("kind" = inline(Option<String>), Query, description = "honeypot.event kind (command, login, ...)."),
        ("shasum" = inline(Option<String>), Query, description = "Captured-payload hash."),
        ("community_id" = inline(Option<String>), Query, description = "One flow across every sensor that saw it."),
        ("q" = inline(Option<String>), Query, description = "Free-text query_string, passed to Elasticsearch as-is."),
        ("since" = inline(Option<String>), Query, description = "Go-style relative window (24h, 7d)."),
        ("persona" = inline(Option<String>), Query, description = "Decoy persona id."),
        ("site" = inline(Option<String>), Query, description = "Decoy site id."),
        ("asset" = inline(Option<String>), Query, description = "Decoy asset id."),
        ("fingerprint" = inline(Option<String>), Query, description = "Client fingerprint, matched across every field sensors record one in."),
        ("cmd" = inline(Option<String>), Query, description = "Exact command text."),
        ("cred" = inline(Option<String>), Query, description = "\"user / pass\" pair."),
        ("path" = inline(Option<String>), Query, description = "Request path."),
        ("session" = inline(Option<String>), Query, description = "Session id."),
        ("asn" = inline(Option<String>), Query, description = "Source AS number."),
        ("org" = inline(Option<String>), Query, description = "Source network organization."),
        ("provider" = inline(Option<String>), Query, description = "Provider class."),
        ("sig" = inline(Option<String>), Query, description = "IDS alert signature."),
        ("cat" = inline(Option<String>), Query, description = "Detection category (Suricata alert category or honeypot.category)."),
    ),
    responses(
        (status = 200, description = "Behaviour-search rows as JSON.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/export/history.json — the same honeypot-v2-*/suricata-v2-*
/// query events::list serves, just forced to the export cap and marked as
/// a download. Mirrors elastic.go's history(attachment=true).
pub async fn history_json(
    State(state): State<AppState>,
    Query(mut q): Query<EventsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    q.size = 500;
    let filters = build_filters(&q);
    let body = json!({
        "size": 500,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}}
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"honeypot-history.json\"".to_string()),
        ],
        result.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::row_from_source;
    use serde_json::json;

    // #3213: a CSV is the least supervised read surface in the product. It
    // leaves the browser, lands in someone's spreadsheet, and is read by
    // whatever script the next person writes against it -- so the two facts
    // this file now has to keep true are (a) no captured value leaves in the
    // cells, and (b) the header and the cells still agree on the width.
    // `csv_body` itself cannot check the second: it joins whatever it is
    // given, so a column added to the header and forgotten in the row, or
    // the reverse, produces a file that opens and is silently wrong.

    const SECRET: &str = "correct-horse-battery-staple-9f2c";

    fn stored_login() -> Value {
        json!({
            "@timestamp": "2026-09-01T00:00:00Z",
            "event": {"sensor": "http-honeypot"},
            "honeypot": {
                "sensor": "http-honeypot",
                "src_ip": "203.0.113.9",
                "method": "POST",
                "path": "/wp-login.php",
                "body": format!("log=admin&pwd={SECRET}&wp-submit=Log+In"),
                "query": format!("redirect_to=/wp-admin&password={SECRET}"),
                "username": "admin",
                "password": SECRET,
                "credential_status": "extracted",
                "auth_outcome": "simulated"
            }
        })
    }

    fn rendered_csv() -> String {
        let row = row_from_source(&stored_login());
        csv_body(EVENTS_CSV_COLUMNS, &[events_csv_row(&row)])
    }

    #[test]
    fn a_stored_password_never_reaches_a_downloaded_cell() {
        let out = rendered_csv();
        assert!(!out.contains(SECRET), "a stored password reached the CSV: {out}");
    }

    #[test]
    fn the_column_width_holds_because_nobody_counted() {
        // The invariant this test exists to protect: `EVENTS_CSV_COLUMNS`
        // and `events_csv_row` are two hand-maintained lists, and #3213
        // added two entries to each. There is no type that ties them
        // together, so the pairing is asserted instead.
        let row = row_from_source(&stored_login());
        let cells = events_csv_row(&row);
        assert_eq!(
            cells.len(),
            EVENTS_CSV_COLUMNS.len(),
            "events.csv would have a header of {} columns and rows of {}",
            EVENTS_CSV_COLUMNS.len(),
            cells.len()
        );
    }

    #[test]
    fn the_two_new_axes_sit_next_to_the_account_and_not_next_to_the_value() {
        // Position is the whole mechanism here — a CSV has no field names, so
        // "credential_status" only describes the cell under it. This also
        // documents the deliberate order: account, value, was-there-one,
        // could-we-read-it, was-the-auth-real.
        let cells = events_csv_row(&row_from_source(&stored_login()));
        let at = |name: &str| EVENTS_CSV_COLUMNS.iter().position(|c| *c == name).unwrap();
        assert_eq!(cells[at("username")], "admin");
        assert_eq!(cells[at("password")], "", "a pre-scrub value reached a cell");
        assert_eq!(cells[at("credential_status")], "extracted");
        assert_eq!(cells[at("auth_outcome")], "simulated");
    }

    #[test]
    fn the_as_columns_read_the_fields_the_ingest_writes() {
        // #3704: field names as `_field_caps` reports them on honeypot-v2.
        let mut src = stored_login();
        src["source"] = json!({
            "as": {"asn": 14061, "organization_name": "DIGITALOCEAN-ASN"}
        });
        let cells = events_csv_row(&row_from_source(&src));
        let at = |name: &str| EVENTS_CSV_COLUMNS.iter().position(|c| *c == name).unwrap();
        assert_eq!(cells[at("asn")], "14061");
        assert_eq!(cells[at("organization")], "DIGITALOCEAN-ASN");
    }

    #[test]
    fn a_document_indexed_before_the_sensors_were_fixed_still_exports_clean() {
        // The scrubber reads what a document says, so a password captured
        // last month is redacted on download now, without a reindex. This is
        // the case that cannot be fixed sensor-side, which is why the
        // boundary exists at all.
        let mut src = stored_login();
        src["honeypot"]["credential_status"] = Value::Null;
        src["honeypot"]["auth_outcome"] = Value::Null;
        let out = csv_body(EVENTS_CSV_COLUMNS, &[events_csv_row(&row_from_source(&src))]);
        assert!(!out.contains(SECRET), "a historical password reached the CSV: {out}");
    }
}
